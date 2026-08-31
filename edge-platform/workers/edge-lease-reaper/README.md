# Edge lease reaper

This Worker is intentionally a fallback, not the normal lifecycle path.  The
Windows shutdown task calls the controller's `destroy` operation first.  While
Windows is healthy, `renew-edge-lease.ps1` sends a sixty-minute lease to the
Worker.  The Worker runs every fifteen minutes and deletes only a matching
`waw-edge-*` Vultr instance after the lease has been expired for thirty minutes.

The deployed Worker has three Worker Secrets: the Vultr lifecycle key, the
narrow Cloudflare DNS key, and the lease-renewal bearer token.  No value is
stored in this directory or in a deployment configuration file.
