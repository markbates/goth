# Goth

Package goth provides a simple, clean, and idiomatic way to write authentication
packages for Go web applications.

Unlike other similar packages, Goth, let's you write OAuth, OAuth2, or any other
protocol providers, as long as they implement the `Provider` and `Session` interfaces.

This package was inspired by [https://github.com/intridea/omniauth](https://github.com/intridea/omniauth).

## Installation

```text
$ go get github.com/markbates/goth
```

## Examples

See the [examples](examples) folder for a working application that let's users authenticate
through Twitter or Facebook.

## Issues

Issues always stand a significantly better chance of getting fixed if the are accompanied by a
pull request.

## Contributing

Would I love to see more providers? Certainly! Would you love to contribute one? Hopefully, yes!

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Write Tests!
4. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create new Pull Request
