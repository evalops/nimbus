# GPU Isolation Considerations

Nimbus currently provisions GPU workloads via the Docker-based executor, but several hardening tasks remain before multi-tenant usage can be considered safe.

## Current State

- All GPUs are discovered via `nvidia-smi` and exposed to the executor through Docker’s `device_requests`. There is no MIG partitioning, per-job cgroup, or NVML scoping.
- Containers receive `CUDA_VISIBLE_DEVICES` limited to the allocated devices, but NVML queries can still reveal global device information.
- There is no admission control around MIG/MPS configuration; all jobs assume exclusive access.

## Required Work

1. **MIG & MPS Strategy**
   - Decide on sharing model (exclusive GPU vs MIG vs CUDA MPS).
   - Document supported configurations and required driver settings.

2. **Per-job Isolation**
   - Configure `nvidia-container-runtime` with per-job device cgroups.
   - Restrict `/dev/nvidia*` device nodes to allocated instances only.
   - Implement NVML filtering (e.g., via container runtime args or LD_PRELOAD) to prevent topology leakage.

3. **Scheduling & Labels**
   - Extend labels to express MIG profiles (e.g., `gpu:mig-1g.5gb`).
   - Ensure scheduler prevents over-commit by tracking available partitions.

4. **Attestation & Monitoring**
   - Capture MIG/GDS state in agent telemetry.
   - Alert on unexpected configuration changes or high utilisation.

5. **Testing**
   - Add integration tests that run concurrent GPU jobs ensuring isolation (no cross-job visibility).
   - Include red-team scenarios (bus probing, NVML enumeration, PCI scans) to verify controls.

Until these items are addressed, document that GPU workloads must be run in dedicated hosts without untrusted tenants.
