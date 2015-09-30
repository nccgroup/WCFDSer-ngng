# INSTALL

## Requirements

WCF Deserializer needs a working .NET Environment.  This means either MS Windows or any platform supported by [Mono](http://www.mono-project.com/docs/about-mono/supported-platforms/).

## Getting Started

Edit the config file: `config/wcfdser.properties`

### Windows

```dosini
monopath=
nbfspath=/path/to/nbfs
```

### OS X / Linux / BSD / etc

```dosini
monopath=/path/to/mono
nbfspath=/path/to/nbfs
```

Move the config file into Burp's root directory and load the plugin.
