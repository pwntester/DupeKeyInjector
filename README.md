# Dupe Key Injector

Dupe Key Injetctor is a Burp Suite extension implementing `Dupe Key Confusion`, a new XML signature bypass technique presented at BSides/BlackHat/DEFCON 2019 "SSO Wars: The Token Menace" presentation. 

## Description
`Dupe Key Confusion` is a new attack to bypass XML signature verification by sending multiple key identifiers in the KeyInfo section. Vulnerable systems will use the first one to verify the XML signature and the second one to verify the trust on the signing party. This plugin applies this technique to SAML tokens by allowing to modify and then resign the SAML assertion with an arbitrary attacker-controlled key which is then send as the first element of the KeyInfo section, while the original key identifier is sent as the second key identifier.

For more details about this technique, please refer to the following materials:
- [White paper](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/whitepaper.pdf)
- [Slides](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/slides.pdf)
- [Exchange RCE Demo](https://youtu.be/bUf5CrjtpiQ)
- [Exchange Account Takeover Demo](https://youtu.be/N1eC7MxgyJc)
- [Sharepoint Privilege Escalation Demo](https://youtu.be/JnKpecoyyDA)

## Screenshot
<img src="/resources/screenshot.png" width="600" height="625" />

## Usage
Intercept a SAML request and use the `Dupe Key Injector` tab to modify the assertion and then re-sign it using one of the following techniques:
- Re-sign with RSA key. 
- Re-sign with public certificate (only enabled when a public base64 certificate has been imported). 

## Build
`mvn package`

## Authors
This plugin was developed as part of a Micro Focus Fortify research by:
- Alvaro Muñoz ([@pwntester](https://twitter.com/pwntester/))
- Oleksandr Mirosh ([@OlekMirosh](https://twitter.com/OlekMirosh/))

## Thanks
This plugin is strongly based on [SAML Raider](https://github.com/SAMLRaider/SAMLRaider). It actually uses many of the helper methods to process SAML tokens and XML documents from this project.

## License
MIT License
