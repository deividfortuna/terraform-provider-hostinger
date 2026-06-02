package hostinger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

// FirewallAction mirrors VPS.V1.Action.ActionResource.
type FirewallAction struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

func resourceHostingerVPSFirewallActivation() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceHostingerVPSFirewallActivationCreate,
		ReadContext:   resourceHostingerVPSFirewallActivationRead,
		UpdateContext: resourceHostingerVPSFirewallActivationUpdate,
		DeleteContext: resourceHostingerVPSFirewallActivationDelete,
		Importer: &schema.ResourceImporter{
			StateContext: resourceHostingerVPSFirewallActivationImport,
		},
		Schema: map[string]*schema.Schema{
			"firewall_id": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     true,
				Description:  "ID of the firewall to activate on the virtual machine.",
				ValidateFunc: validation.IntAtLeast(1),
			},
			"virtual_machine_id": {
				Type:         schema.TypeInt,
				Required:     true,
				ForceNew:     true,
				Description:  "ID of the virtual machine to activate the firewall on. Only one firewall can be active on a VM at a time.",
				ValidateFunc: validation.IntAtLeast(1),
			},
			"triggers": {
				Type:        schema.TypeMap,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Arbitrary map whose change triggers a firewall sync on the virtual machine. Use it to re-apply rules after they change, e.g. triggers = { rules = sha1(jsonencode(hostinger_vps_firewall.web.rule)) }.",
			},
			"is_synced": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "The firewall's global sync state, as reported by the firewall API (not specific to this virtual machine). Changing the firewall's rules sets this to false until a sync is performed.",
			},
		},
	}
}

func resourceHostingerVPSFirewallActivationCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*HostingerClient)
	firewallID := d.Get("firewall_id").(int)
	vmID := d.Get("virtual_machine_id").(int)

	if _, err := client.ActivateFirewall(ctx, firewallID, vmID); err != nil {
		return diag.FromErr(fmt.Errorf("failed to activate firewall %d on VM %d: %w", firewallID, vmID, err))
	}

	d.SetId(fmt.Sprintf("%d/%d", firewallID, vmID))
	return resourceHostingerVPSFirewallActivationRead(ctx, d, m)
}

func resourceHostingerVPSFirewallActivationRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*HostingerClient)

	firewallID, vmID, err := parseFirewallActivationID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	// Detect drift on this specific VM: the VM reports the firewall currently active
	// on it via firewall_group_id. If it no longer points at our firewall (deactivated
	// out-of-band, or another firewall activated on the VM — only one can be active at a
	// time), the activation is gone, so drop it from state.
	vm, err := client.GetVirtualMachine(vmID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(fmt.Errorf("failed to read virtual machine %d: %w", vmID, err))
	}
	if vm.FirewallGroupID == nil || *vm.FirewallGroupID != firewallID {
		d.SetId("")
		return nil
	}

	fw, err := client.GetFirewall(firewallID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			d.SetId("")
			return nil
		}
		return diag.FromErr(fmt.Errorf("failed to read firewall %d: %w", firewallID, err))
	}

	if err := d.Set("firewall_id", firewallID); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set firewall_id: %w", err))
	}
	if err := d.Set("virtual_machine_id", vmID); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set virtual_machine_id: %w", err))
	}
	if err := d.Set("is_synced", fw.IsSynced); err != nil {
		return diag.FromErr(fmt.Errorf("failed to set is_synced: %w", err))
	}

	return nil
}

func resourceHostingerVPSFirewallActivationUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*HostingerClient)

	// Only "triggers" is updatable; firewall_id and virtual_machine_id are ForceNew.
	// A change to triggers re-applies (syncs) the firewall to the VM.
	if d.HasChange("triggers") {
		firewallID, vmID, err := parseFirewallActivationID(d.Id())
		if err != nil {
			return diag.FromErr(err)
		}
		if _, err := client.SyncFirewall(ctx, firewallID, vmID); err != nil {
			return diag.FromErr(fmt.Errorf("failed to sync firewall %d on VM %d: %w", firewallID, vmID, err))
		}
	}

	return resourceHostingerVPSFirewallActivationRead(ctx, d, m)
}

func resourceHostingerVPSFirewallActivationDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*HostingerClient)

	firewallID, vmID, err := parseFirewallActivationID(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}

	if _, err := client.DeactivateFirewall(ctx, firewallID, vmID); err != nil {
		return diag.FromErr(fmt.Errorf("failed to deactivate firewall %d on VM %d: %w", firewallID, vmID, err))
	}

	d.SetId("")
	return nil
}

func resourceHostingerVPSFirewallActivationImport(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	if _, _, err := parseFirewallActivationID(d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

// parseFirewallActivationID splits a "firewallId/virtualMachineId" composite ID.
func parseFirewallActivationID(id string) (int, int, error) {
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid firewall activation ID %q: expected \"firewallId/virtualMachineId\"", id)
	}
	firewallID, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid firewall ID in %q: %w", id, err)
	}
	vmID, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid virtual machine ID in %q: %w", id, err)
	}
	// The schema requires both IDs to be >= 1; enforce the same bound here so import
	// and refresh reject invalid IDs early instead of building requests against them.
	if firewallID < 1 || vmID < 1 {
		return 0, 0, fmt.Errorf("invalid firewall activation ID %q: firewall and virtual machine IDs must be >= 1", id)
	}
	return firewallID, vmID, nil
}

// HostingerClient implementations:

func (c *HostingerClient) ActivateFirewall(ctx context.Context, firewallID, vmID int) (*FirewallAction, error) {
	return c.firewallVMAction(ctx, "activate", firewallID, vmID)
}

func (c *HostingerClient) DeactivateFirewall(ctx context.Context, firewallID, vmID int) (*FirewallAction, error) {
	return c.firewallVMAction(ctx, "deactivate", firewallID, vmID)
}

func (c *HostingerClient) SyncFirewall(ctx context.Context, firewallID, vmID int) (*FirewallAction, error) {
	return c.firewallVMAction(ctx, "sync", firewallID, vmID)
}

// firewallActionTimeout bounds how long firewallVMAction waits for an accepted
// activate/deactivate/sync action to settle before giving up. A sync can take up to
// ~8 minutes, so this is set well above that; it stays within Terraform's default
// 20-minute resource operation timeout.
const firewallActionTimeout = 10 * time.Minute

// firewallVMAction performs one of the activate/deactivate/sync firewall operations,
// which share an identical request/response shape, and waits for the accepted action
// to settle before returning.
func (c *HostingerClient) firewallVMAction(ctx context.Context, action string, firewallID, vmID int) (*FirewallAction, error) {
	url := fmt.Sprintf("%s/api/vps/v1/firewall/%d/%s/%d", c.BaseURL, firewallID, action, vmID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s firewall request: %w", action, err)
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%s firewall failed (HTTP %d): %s", action, resp.StatusCode, msg)
	}

	var res FirewallAction
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	// A 200 only means the action was accepted; the action itself runs asynchronously
	// and reports progress via its state (success|error|delayed|sent|created). Wait for
	// it to reach "success" so a still-pending action is not reported as a finished apply
	// (which would make the follow-up Read see the firewall not yet active on the VM and
	// drop the resource from state), and so a failed action surfaces as a hard error.
	return c.waitForFirewallAction(ctx, action, vmID, &res)
}

// waitForFirewallAction polls a firewall action until it reaches a terminal state:
// "success" returns the action, "error" returns an error, and the pending states
// (created/sent/delayed) are re-fetched from the action endpoint until they settle
// or firewallActionTimeout elapses. The caller's context is honoured, so polling stops
// promptly when Terraform cancels the operation.
func (c *HostingerClient) waitForFirewallAction(ctx context.Context, action string, vmID int, current *FirewallAction) (*FirewallAction, error) {
	err := retry.RetryContext(ctx, firewallActionTimeout, func() *retry.RetryError {
		switch current.State {
		case "success":
			return nil
		case "error":
			return retry.NonRetryableError(fmt.Errorf("%s firewall action %d reported state %q", action, current.ID, current.State))
		}
		// Pending (created/sent/delayed): re-fetch the action and retry until it settles.
		next, err := c.GetVMAction(ctx, vmID, current.ID)
		if err != nil {
			return retry.NonRetryableError(fmt.Errorf("failed to poll %s firewall action %d: %w", action, current.ID, err))
		}
		current = next
		return retry.RetryableError(fmt.Errorf("%s firewall action %d still in state %q", action, current.ID, current.State))
	})
	if err != nil {
		return current, err
	}
	return current, nil
}

// GetVMAction retrieves the current state of an asynchronous action previously
// submitted against a virtual machine.
func (c *HostingerClient) GetVMAction(ctx context.Context, vmID, actionID int) (*FirewallAction, error) {
	url := fmt.Sprintf("%s/api/vps/v1/virtual-machines/%d/actions/%d", c.BaseURL, vmID, actionID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create get action request: %w", err)
	}
	c.addStandardHeaders(req)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get action failed (HTTP %d): %s", resp.StatusCode, msg)
	}

	var res FirewallAction
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}
