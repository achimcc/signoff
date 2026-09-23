# signoff

Is the service really done?

A service that is deployed, green in `systemctl` and answering on its own
port can still be unusable: its name resolves to the CDN's wildcard instead
of the VPS, the VPS's SNI map does not know it, the reverse proxy cannot
reach its backend across a zone edge, the identity provider's outpost does
not carry its provider, no backup snapshot exists yet, or the vendor's
default account still logs in. Each of these has happened here, each with a
green deploy. `signoff check <service>` asks these questions live, in one
call, with one verdict per question.

## Usage

(filled in by the final task)

## License

AGPL-3.0-only.
