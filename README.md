# notpass-go

A collection of tools for managing passwords and working with other password managers.

* `phrases` generates passphrases for cases where a human needs to remember the password. (For
example, you might use this to generate a master password for your password manager.)
* `pwsafe` provides read-only access to [PasswordSafe](https://www.pwsafe.org/) v3.x safes,
including safes protected by a YubiKey.

## Prerequisites

You'll need [Go](https://go.dev/) installed and configured.

## Building

On platforms where it is available, `make` is the easiest way to build. For example:

`make phrases`

`make pwsafe`

## Running

Run any command with the `--help` argument to display its usage.

## Acknowledgments

The following projects and references were extremely helpful for sorting out the details of
various file formats and APIs. 

* [PasswordSafe](https://github.com/pwsafe/pwsafe)
* [gopwsafe](https://github.com/tkuhlman/gopwsafe)
* [Java PasswordSafe](https://sourceforge.net/projects/jpwsafe/)
