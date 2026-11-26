package ansible

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type composeServicesDoc struct {
	Services map[string]struct {
		ContainerName string `yaml:"container_name"`
	} `yaml:"services"`
}

type libvirtWarningTask struct {
	Name         string            `yaml:"name"`
	IncludeTasks string            `yaml:"ansible.builtin.include_tasks"`
	VirtNet      map[string]any    `yaml:"community.libvirt.virt_net"`
	Template     map[string]any    `yaml:"ansible.builtin.template"`
	Copy         map[string]any    `yaml:"ansible.builtin.copy"`
	Command      any               `yaml:"ansible.builtin.command"`
	Debug        map[string]any    `yaml:"ansible.builtin.debug"`
	Register     string            `yaml:"register"`
	ChangedWhen  any               `yaml:"changed_when"`
	CheckMode    *bool             `yaml:"check_mode"`
	FailedWhen   any               `yaml:"failed_when"`
	Become       *bool             `yaml:"become"`
	BecomeUser   string            `yaml:"become_user"`
	Environment  map[string]string `yaml:"environment"`
	When         any               `yaml:"when"`
}

// TestWorkstationLibvirtOutOfBandContainersMatchCompose verifies defaults/main.yaml maps every Bastion container declared in compose.yml.
func TestWorkstationLibvirtOutOfBandContainersMatchCompose(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	composePath := filepath.Join(filepath.Dir(ansibleDir), "compose.yml")
	composeDoc := mustReadYAML[composeServicesDoc](t, composePath)

	defaultsPath := filepath.Join(ansibleDir, "roles", "workstation_libvirt", "defaults", "main.yaml")
	defaultsDoc := mustReadYAML[map[string]any](t, defaultsPath)

	rawContainers, ok := defaultsDoc["workstation_libvirt_out_of_band_containers"]
	if !ok {
		t.Fatalf("defaults/main.yaml missing key workstation_libvirt_out_of_band_containers")
	}
	containers, ok := rawContainers.(map[string]any)
	if !ok {
		t.Fatalf("workstation_libvirt_out_of_band_containers has type %T, want mapping", rawContainers)
	}

	serviceMapping := map[string]string{
		"vault_server":               "vault-server",
		"vault_terminator":           "vault-terminator",
		"vault_telemetry_terminator": "vault-telemetry-terminator",
	}
	keys := make([]string, 0, len(serviceMapping))
	for k := range serviceMapping {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	for _, defaultKey := range keys {
		composeSvc := serviceMapping[defaultKey]
		svc, exists := composeDoc.Services[composeSvc]
		if !exists || svc.ContainerName == "" {
			t.Fatalf("compose.yml service %q missing container_name", composeSvc)
		}
		got, _ := containers[defaultKey].(string)
		if got != svc.ContainerName {
			t.Errorf("workstation_libvirt_out_of_band_containers[%q] = %q, want %q", defaultKey, got, svc.ContainerName)
		}
	}
}

// TestWorkstationLibvirtDeclaresOutOfBandWarningTasks verifies change registration, rootless Podman inspection, and warning emission.
func TestWorkstationLibvirtDeclaresOutOfBandWarningTasks(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	tasksDir := filepath.Join(ansibleDir, "roles", "workstation_libvirt", "tasks")

	mainTasks := mustReadYAML[[]libvirtWarningTask](t, filepath.Join(tasksDir, "main.yaml"))
	hasWarningInclude := false
	for _, task := range mainTasks {
		if task.IncludeTasks == "F-out-of-band-warnings.yaml" {
			hasWarningInclude = true
			break
		}
	}
	if !hasWarningInclude {
		t.Errorf("tasks/main.yaml missing include_tasks for F-out-of-band-warnings.yaml")
	}

	assertLibvirtNetworkTasksRegistered(t, filepath.Join(tasksDir, "B-publish-network.yaml"))
	assertLibvirtVaultConfigTasksRegistered(t, filepath.Join(tasksDir, "E-vault-config.yaml"))
	assertLibvirtOutOfBandWarningFile(t, filepath.Join(tasksDir, "F-out-of-band-warnings.yaml"))
}

func assertLibvirtNetworkTasksRegistered(t *testing.T, path string) {
	t.Helper()
	tasks := mustReadYAML[[]libvirtWarningTask](t, path)
	sawDefine, sawActive := false, false
	for _, task := range tasks {
		if task.VirtNet == nil {
			continue
		}
		if task.VirtNet["command"] == "define" {
			sawDefine = true
			if task.Register == "" {
				t.Errorf("%s task %q must set register", filepath.Base(path), task.Name)
			}
		}
		if task.VirtNet["state"] == "active" {
			sawActive = true
			if task.Register == "" {
				t.Errorf("%s task %q must set register", filepath.Base(path), task.Name)
			}
		}
	}
	if !sawDefine || !sawActive {
		t.Errorf("%s missing expected virt_net define (%v) or active (%v) task", filepath.Base(path), sawDefine, sawActive)
	}
}

func assertLibvirtVaultConfigTasksRegistered(t *testing.T, path string) {
	t.Helper()
	base := filepath.Base(path)
	tasks := mustReadYAML[[]libvirtWarningTask](t, path)
	requiredTemplates := map[string]bool{
		"vault.hcl.j2":             false,
		"haproxy.cfg.j2":           false,
		"haproxy-telemetry.cfg.j2": false,
	}
	sawCopy := false
	for _, task := range tasks {
		if src, ok := templateTaskSrc(task); ok {
			recordTrackedTemplateTask(t, base, task, src, requiredTemplates)
		}
		if task.Copy != nil {
			sawCopy = true
			assertTaskRegistered(t, base, task, "copy")
		}
	}
	for src, found := range requiredTemplates {
		if !found {
			t.Errorf("%s missing template task for %s", base, src)
		}
	}
	if !sawCopy {
		t.Errorf("%s missing copy task for container environment files", base)
	}
}

func templateTaskSrc(task libvirtWarningTask) (string, bool) {
	if task.Template == nil {
		return "", false
	}
	src, ok := task.Template["src"].(string)
	return src, ok
}

func recordTrackedTemplateTask(t *testing.T, base string, task libvirtWarningTask, src string, requiredTemplates map[string]bool) {
	t.Helper()
	if _, tracked := requiredTemplates[src]; !tracked {
		return
	}
	requiredTemplates[src] = true
	assertTaskRegistered(t, base, task, src)
}

func assertTaskRegistered(t *testing.T, base string, task libvirtWarningTask, label string) {
	t.Helper()
	if task.Register == "" {
		t.Errorf("%s task %q (%s) must set register", base, task.Name, label)
	}
}

func assertLibvirtOutOfBandWarningFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("missing warning task file %s: %v", filepath.Base(path), err)
		return
	}
	tasks := mustReadYAML[[]libvirtWarningTask](t, path)
	sawPodmanProbe := false
	sawDebugWarn := false
	for _, task := range tasks {
		if task.Command != nil && commandContainsPodmanPS(task.Command) {
			sawPodmanProbe = true
			assertPodmanProbeTask(t, path, task)
		}
		if task.Debug != nil {
			sawDebugWarn = true
			assertWarningDebugTask(t, path, task)
		}
	}
	if !sawPodmanProbe {
		t.Errorf("%s missing rootless podman ps command task", filepath.Base(path))
	}
	if !sawDebugWarn {
		t.Errorf("%s missing ansible.builtin.debug warning task", filepath.Base(path))
	}
}

func commandContainsPodmanPS(cmd any) bool {
	text := strings.ToLower(fmt.Sprint(cmd))
	return strings.Contains(text, "podman") && strings.Contains(text, "ps")
}

func assertPodmanProbeTask(t *testing.T, path string, task libvirtWarningTask) {
	t.Helper()
	base := filepath.Base(path)
	if task.ChangedWhen != false {
		t.Errorf("%s task %q must set changed_when: false", base, task.Name)
	}
	if task.CheckMode == nil || *task.CheckMode {
		t.Errorf("%s task %q must set check_mode: false", base, task.Name)
	}
	if task.FailedWhen != false {
		t.Errorf("%s task %q must set failed_when: false", base, task.Name)
	}
	if task.BecomeUser != "{{ workstation_libvirt_operator_user }}" {
		t.Errorf("%s task %q become_user = %q, want %q", base, task.Name, task.BecomeUser, "{{ workstation_libvirt_operator_user }}")
	}
	if task.Environment["XDG_RUNTIME_DIR"] == "" {
		t.Errorf("%s task %q must set environment.XDG_RUNTIME_DIR", base, task.Name)
	}
	if task.Register == "" {
		t.Errorf("%s task %q must set register", base, task.Name)
	}
}

func assertWarningDebugTask(t *testing.T, path string, task libvirtWarningTask) {
	t.Helper()
	base := filepath.Base(path)
	if task.When == nil || strings.TrimSpace(fmt.Sprint(task.When)) == "" {
		t.Errorf("%s task %q must gate debug warning with a non-empty when condition", base, task.Name)
	}
	msg, _ := task.Debug["msg"].(string)
	if strings.TrimSpace(msg) == "" {
		t.Errorf("%s task %q must define non-empty debug.msg", base, task.Name)
	}
}
