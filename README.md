# Dupe Key Injector

This plugin implements the XML signature bypass techniques (Dupe Key Confusion) presented at BSides/BlackHat/DEFCON 2019 by Alvaro Muñoz ([@pwntester](https://twitter.com/pwntester/)) and Oleksander Mirosh ([@OlekMirosh](https://twitter.com/OlekMirosh/)). For more details about this technique, please refer to the materials that can be found here:
- https://www.blackhat.com/us-19/briefings/schedule/#sso-wars-the-token-menace-15092 

![screenshot](/screenshot.png)

## Usage
Intercept a SAML request and use the `Dupe Key Injector` tab to modify the assertion and then re-sign it using one of the following techniques:
- Re-sign with RSA key. 
- Re-sign with public certificate (only enabled when a public base64 certificate has been imported). 

## Build
`mvn package`

## License
MIT License

## Credits
This plugin is strongly based on [SAML Raider](https://github.com/SAMLRaider/SAMLRaider). It actually uses many of the helper methods to process SAML tokens and XML documents from this project.

## Authors
- Alvaro Muñoz ([@pwntester](https://github.com/SAMLRaider/SAMLRaider))
- Oleksandr Mirosh ([@OlekMirosh](https://twitter.com/OlekMirosh/))

## Thanks
This plugin was developed as part of a Micro Focus Fortify research

