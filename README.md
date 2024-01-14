# django-auth

![django-auth workflow](https://github.com/mindeng/django-auth/actions/workflows/rust.yml/badge.svg)

Authenticate or generate Django-managed passwords. Written in Rust.

A Django-managed password is a hashed password stored by Django.
See [Password management in Django][1] for more information.

[1]: https://docs.djangoproject.com/en/5.0/topics/auth/passwords/

## Library Usage

See:

- [docs.rs](https://docs.rs/clap/latest/django-auth/)
- [examples](examples/)

## CLI Tool Usage

`cargo run --example auth`:

```example
Authenticate or generate Django-managed passwords

Usage: auth <COMMAND>

Commands:
  encode  Encode a password in Django-style
  verify  Verify a Django stored hashed password
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```
