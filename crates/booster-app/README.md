# booster-app (SystemBooster UI)

Tauri 2 desktop front-end. Runs unprivileged and forwards every action to the
`booster-service` over the named pipe (`\\.\pipe\SystemBooster`).

This crate is **excluded from the root Cargo workspace** because its backend
links system libraries (webkit2gtk on Linux) that aren't present in CI/dev
containers. Build it on a machine with the [Tauri
prerequisites](https://tauri.app/start/prerequisites/) installed.

## Develop / run

```bash
# from this directory, with the Tauri CLI installed (cargo install tauri-cli)
cargo tauri dev
```

The UI is plain static files in `ui/` (no bundler/build step). You can preview
the interface in any browser without the service:

```bash
npx serve ui      # or: python3 -m http.server -d ui
```

In the browser it runs in **preview mode** with mock data; inside the Tauri app
it calls the real backend commands (`scan`, `start_boost`, `end_boost`,
`get_status`, `heartbeat`), which proxy to the service.

## Build the installer

`cargo tauri build` produces the MSI defined in `tauri.conf.json`. The
production installer is also responsible for installing and starting
`booster-service` as a LocalSystem service.
