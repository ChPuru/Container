# Docker Engine API compatibility

hull serves Docker Engine API **v1.43** (accepting down to v1.24) so the stock `docker` CLI,
`docker compose`, VS Code Dev Containers and Testcontainers work against it unchanged. This is
the conformance checklist: what must work, and the specific behaviours that clients break on.

Run the harness with `make e2e` once `test/conformance/` lands. Until then this is the spec.

## Tier 1 — nothing works without these

| Endpoint | Client that depends on it |
|---|---|
| `GET /_ping`, `HEAD /_ping` | every client's version negotiation |
| `GET /version`, `GET /info` | `docker version`, compose's feature gates |
| `POST /containers/create` | everything |
| `POST /containers/{id}/start`, `/stop`, `/kill`, `/wait` | everything |
| `GET /containers/json`, `GET /containers/{id}/json` | `ps`, `inspect`, compose reconciliation |
| `DELETE /containers/{id}` | everything |
| `POST /images/create` (pull) | everything |
| `GET /images/json`, `GET /images/{name}/json` | `images`, compose |
| `GET /containers/{id}/logs` | `logs`, compose, Testcontainers' wait strategies |
| `POST /containers/{id}/attach` | `run -it` |
| `POST /containers/{id}/exec` → `POST /exec/{id}/start` | `exec`, Dev Containers, Testcontainers |
| `GET /events` | compose's `up` reconciliation loop |
| networks: `GET/POST /networks`, `/networks/{id}/connect`, `/disconnect` | compose |
| volumes: `GET/POST /volumes`, `DELETE /volumes/{name}` | compose |

## Tier 2 — a normal day needs these

`/containers/{id}/stats` · `/top` · `/changes` · `/archive` (GET, HEAD, PUT) · `/export` ·
`/rename` · `/update` · `/pause`, `/unpause` · `/resize` · `/restart` ·
`/images/{name}/push` · `/tag` · `/history` · `/images/get`, `/images/load` · `/commit` ·
`POST /auth` · `/system/df` · every `/prune` · `/distribution/{name}/json`

## Tier 3 — build

`POST /build` plus BuildKit's `/grpc` and `/session`. The modern `docker build` and
`docker compose build` route through buildx, which requires these. Until the native builder
exists, hull proxies to a bundled `buildkitd`; when it is absent, `/build` must return a 501
whose message names `hull engine install-buildkit` rather than failing opaquely.

## Behaviours clients actually break on

These are the ones that look fine in a curl test and then fail against a real client.

1. **Hijack handshake.** `/attach` and `/exec/{id}/start` must reply
   `HTTP/1.1 101 UPGRADED` with `Content-Type: application/vnd.docker.raw-stream`,
   `Connection: Upgrade`, `Upgrade: tcp` — or `200 OK` with that content type when the client
   did not send an `Upgrade` header — and then speak the raw stream on the hijacked conn.
2. **Stream framing.** Without a TTY, output is multiplexed with the 8-byte header
   `[stream(1)][0][0][0][size uint32 BE]`. With a TTY, bytes pass through unframed. Getting this
   backwards produces garbage on the terminal, not an error.
3. **The leading slash on names.** `Name` in container inspect is `/web`, not `web`. Compose
   matches on it.
4. **Error message text, not just status.** Compose and Testcontainers match strings:
   `No such container: <id>`, `No such image: <ref>`, `Conflict. The container name "/x" is
   already in use by container "<id>"`. Status codes: 400 bad parameter, 404 not found,
   409 conflict, 500 server error.
5. **Errors inside a 200 stream.** `/images/create`, `/images/load`, `/build` and `/push` have
   already sent their headers, so a failure is a final JSON object
   `{"errorDetail":{"message":"…"},"error":"…"}` in the stream — with a 200 status.
   Flush after every object or the client's progress display hangs.
6. **`filters` is a JSON object of `string -> []string`.** Different keys AND together, repeated
   values of one key OR together. Unknown keys must be rejected the way Docker rejects them.
7. **`/events` must replay from `since`** before streaming live, or compose misses the container
   it just created.
8. **`/wait` conditions**: `not-running` (default), `next-exit`, `removed`.
9. **`/containers/json?all=1` status strings** are exactly `created|running|paused|restarting|
   removing|exited|dead`, and `Status` is the human form (`Up 3 minutes`, `Exited (0) 1 hour ago`).
10. **`Ports`** in the list response use `PrivatePort`/`PublicPort`/`Type`/`IP`, while `inspect`
    uses the `NetworkSettings.Ports` map of `"80/tcp" -> [{HostIp, HostPort}]`. They are different
    shapes for the same data; both must be right.
11. **Version prefix.** Every path may be prefixed `/v1.43/`. Parse it, gate on it, and reject
    versions outside the supported range with a 400.
12. **`/_ping` response headers** carry `Api-Version`, `Docker-Experimental`, `OSType`,
    `Builder-Version` and `Cache-Control: no-cache`. Clients read them before anything else.

## Known deliberate gaps

| Gap | Why | Client impact |
|---|---|---|
| Swarm (`/services`, `/nodes`, `/swarm`, `/tasks`, `/secrets`, `/configs`) | hull is single-host | `docker stack` does not work; nothing else notices |
| Plugins (`/plugins`) | no plugin system | none in practice |
| Log drivers beyond `json-file` and `none` | scope | `--log-driver syslog` errors clearly |
| ~~`/containers/{id}/attach/ws`~~ | — | **now implemented**: a hand-rolled RFC 6455 handshake and framing, no new dependency. Stricter than the raw attach, and deliberately so: it requires a running container, which is what moby does too |
| Schema 1 images | removed from the ecosystem in 2025 | very old tags fail with an explicit message |
| Checkpoints (`/checkpoints`) | CRIU is a later milestone | hull's own `snapshot` verbs cover the useful case |

## Gaps found by running it

These are real and open, each with an owner. None of them breaks a client outright.

| Gap | Effect | Owner |
|---|---|---|
| `X-Registry-Auth` is decoded and validated, then dropped | a private-registry pull falls back to the daemon's own keychain instead of the caller's credentials | `engine.Pull`/`Push` need a credentials parameter |
| `?size=1` reports `SizeRw`/`SizeRootFs` as 0 | fields are present and correctly typed, so nothing breaks; the numbers are just not computed | `engine.List` ignores `ListOptions.Size` |
| no per-container activity signal | a live client keeps the *daemon* awake but not an individual container, so scale-to-zero could freeze something a client is watching | `engine` needs an exported `Touch(id)` |
| `hulld` does not record which containers it froze | after a restart, an engine-initiated freeze is indistinguishable from a user's `pause`, and the watcher correctly refuses to undo it | `hulld` must persist and call `idle.Reclaim` |
| `hull cp -L` only follows links one way | `hull cp -L ctr:/link ./x` copies the link, not its target | one-line fix in `copyFromContainer` |

## Verifying

```bash
# point the real docker CLI at hull and run its own commands against it
export DOCKER_HOST=unix:///var/lib/hull/run/hull.sock
docker version && docker info
docker run --rm alpine echo hello
docker run -d --name web -p 8080:80 nginx && curl -sf localhost:8080 >/dev/null && echo ok
docker exec web nginx -v
docker logs web
docker compose -f test/conformance/compose.yaml up -d
```

Testcontainers is the harshest realistic test: it exercises create, start, logs with a wait
strategy, exec, port mapping, and remove, and it fails loudly on any shape mismatch.
