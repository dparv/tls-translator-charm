# Certificate Translator Charm

A Juju charm that bridges the legacy `tls-certificates` v1 interface used by
older OpenStack reactive charms with the modern `tls-certificates` v4 interface
used by providers such as [lego](https://charmhub.io/lego),
[vault](https://charmhub.io/vault), and
[self-signed-certificates](https://charmhub.io/self-signed-certificates).

## Problem

Many production OpenStack deployments rely on reactive charms (Keystone, Nova,
Neutron, etc.) that request TLS certificates through the v1
`tls-certificates` interface. Modern certificate providers have moved to the v4
interface and no longer speak v1. This charm sits between the two, translating
requests and responses so that legacy workloads can obtain certificates from
modern providers without modification.

## How It Works

```
┌──────────────┐   v1 relation    ┌─────────────────────┐   v4 relation    ┌──────────────┐
│  Legacy charm │ ──────────────► │ Certificate         │ ──────────────► │  Modern TLS  │
│  (Keystone,   │  cert_requests  │ Translator          │  CSR via lib    │  Provider    │
│   Nova, etc.) │ ◄────────────── │                     │ ◄────────────── │  (lego, etc.)│
│              │  cert + CA       │                     │  signed cert    │              │
└──────────────┘                  └─────────────────────┘                  └──────────────┘
```

1. **Parses v1 requests** -- Reads `cert_requests`, `client_cert_requests`,
   and `application_cert_requests` from the legacy relation databag.
2. **Filters domains** -- Drops non-public domains (`.lxd`) and RFC 1918 IP
   addresses that cannot be validated by public ACME providers.
3. **Generates v4 CSRs** -- Creates `CertificateRequestAttributes` and
   delegates to `TLSCertificatesRequiresV4.sync()` for CSR lifecycle
   management.
4. **Publishes certificates** -- When a signed certificate is received from the
   v4 provider, it is written back to the v1 relation in the format legacy
   charms expect (`cert`, `key`, `ca`, `chain`).

## Requirements

- Juju 3.x
- Ubuntu 24.04 (Noble) base
- Python >= 3.10

## Deployment

```bash
juju deploy ./certificate-translator
juju deploy self-signed-certificates

# Connect a legacy charm (e.g. keystone) to the translator
juju relate keystone:certificates certificate-translator:legacy-certificates

# Connect the translator to a modern TLS provider
juju relate certificate-translator:certificates self-signed-certificates:certificates
```

## Relations

| Endpoint              | Interface           | Role     | Description                                      |
|-----------------------|---------------------|----------|--------------------------------------------------|
| `legacy-certificates` | `tls-certificates`  | Provider | Serves certificates to legacy v1 charms          |
| `certificates`        | `tls-certificates`  | Requirer | Requests certificates from a modern v4 provider  |
| `cluster`             | `cluster`           | Peer     | Peer relation for future HA coordination         |

## Supported Legacy Request Formats

- **Server certificate requests** (`cert_requests`) -- batch format with CN and
  SANs.
- **Client certificate requests** (`client_cert_requests`) -- for charms like
  ovn-central that need client certificates.
- **Application certificate requests** (`application_cert_requests`) --
  application-scoped requests shared across units.

## Development

### Prerequisites

```bash
sudo snap install charmcraft --classic
pip install tox
```

### Running Tests

```bash
tox -e unit
```

### Building the Charm

```bash
charmcraft pack
```

## Architecture

- **Framework**: [ops](https://juju.is/docs/sdk) (Charmed Operator Framework)
- **State management**: `StoredState` with JSON-serialized dataclass records
- **TLS library**: `charmlibs.interfaces.tls_certificates` v4 (PyPI dependency)
- **Testing**: `ops-scenario` with `ops.testing.Context`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run `tox -e unit` to verify tests pass
4. Open a pull request

## License

This project is open source. See the repository for license details.
