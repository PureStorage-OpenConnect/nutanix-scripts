# Portworx Node Prep DaemonSet

A Kubernetes `DaemonSet` that prepares cluster nodes for running Portworx with Everpure FlashArray (NVMe-oF/TCP) backends. It configures multipathing, disables the in-kernel NVMe multipath handler in favor of `device-mapper-multipath`, and persists the change across reboots.

Built for and tested on **Nutanix Kubernetes Platform (NKP)** clusters.

## What it does

On every node in the cluster, the DaemonSet runs a privileged container that uses `nsenter` to execute directly in the host namespace. The prep script:

1. Checks `/etc/default/grub` for `nvme_core.multipath=N` and exits early (sleeps forever) if the node has already been prepped, so the container can restart/loop without repeating work.
2. Installs required packages: `nvme-cli`, `device-mapper-multipath`, `kpartx`, `util-linux`.
3. Writes `/etc/multipath.conf` with:
   - A blacklist for Portworx virtual devices (`pxd*`) and VMware virtual disks, so multipath doesn't try to manage them.
   - Device-specific tuning for Everpure `FlashArray` (NVMe and SCSI) targets, including path selector, ALUA priority checker, failback, and timeout settings.
4. Unloads and reloads the NVMe kernel modules (`nvme_core`, `nvme_fabrics`, `nvme_tcp`) with `nvme_core.multipath=N`, disabling native NVMe multipathing so `device-mapper-multipath` takes over.
5. Updates GRUB (`grubby --update-kernel=ALL`) so `nvme_core.multipath=N` persists across node reboots.
6. Enables and restarts `multipathd`.
7. Sleeps forever, keeping the pod alive without restarting.

## Why

Everpure FlashArray NVMe-oF/TCP volumes need to be managed by `device-mapper-multipath` rather than the Linux kernel's native NVMe multipathing, so paths are handled correctly for Portworx. This DaemonSet automates that host-level configuration across every node instead of requiring manual setup.

## Requirements

- A Nutanix Kubernetes Platform (NKP) cluster with nodes running a RHEL-compatible OS (uses `dnf`, `grubby`; image is `rockylinux:9`)
- Ability to schedule privileged pods with `hostPID` and `hostNetwork` in `kube-system`

## Deployment

```bash
kubectl apply -f portworx-node-prep.yaml
```

The DaemonSet tolerates all taints (`operator: Exists`, `effect: NoSchedule`), so it runs on every node, including control-plane nodes.

## Verifying

Check that a node has been prepped:

```bash
kubectl -n kube-system logs -l app=portworx-node-prep <pod-name>
```

A prepped node will show `Node already prepped for Portworx. Sleeping forever.` on subsequent pod restarts. You can also confirm directly on the node:

```bash
grep nvme_core.multipath /etc/default/grub
systemctl status multipathd
```

## Notes

- **Requires a node reboot** to fully apply the `nvme_core.multipath=N` GRUB setting at boot; the script reloads kernel modules live, but a reboot ensures the setting takes effect from boot going forward.
- Runs as a privileged container with `hostPID`, `hostNetwork`, and full namespace access (`nsenter -m -u -n -i -p`) since it needs to modify the host OS directly.
- Review and adjust `/etc/multipath.conf` device settings before use in production if your FlashArray configuration differs.
