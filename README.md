# External Armory

A standalone Sliver Armory implementation for self-hosted Sliver Armories.

### Setup

See the [wiki](https://github.com/sliverarmory/external-armory/wiki/Setup) for the latest installation instructions.

### FAQ

#### Can I override packages from the official Sliver Armory?

Yes, the Sliver client will install packages from 3rd party Armories before checking the official Sliver Armory. This allows you to override packages by creating a private package with the same `command_name`.

#### Is this the same code that the official Sliver Armory uses?

No. The official Sliver Armory is entirely hosted on public GitHub, i.e. none of the official Armory's underlying infrastructure is managed by the Sliver authors. However, this model is not viable for private/3rd party armories, and thus this implementation allows you to self-host your own Armory.

#### Does External Armory support authentication?

Yes, out of the box External Armory supports a simple token authentication scheme, feel free to submit a PR to support other types of authentication.

### License - GPLv3

External Armory is licensed under [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html), some sub-components may have separate licenses.
