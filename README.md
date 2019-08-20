# Dupe Key Injector

Dupe Key Injetctor is a Burp Suite extension implementing "Dupe Key Confusion", a new XML signature bypass technique presented at BSides/BlackHat/DEFCON 2019 "SSO Wars: The Token Menace" presentation. 

## Resources
For more details about this technique, please refer to the following materials:
- [White paper](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/whitepaper.pdf)
- [Slides](https://github.com/pwntester/DupeKeyInjector/blob/master/resources/slides.pdf)
- [Exchange RCE Demo](https://youtu.be/bUf5CrjtpiQ)
- [Exchange Account Takeover Demo](https://youtu.be/N1eC7MxgyJc)
- [Sharepoint Privilege Escalation Demo](https://youtu.be/JnKpecoyyDA)

## Screenshot
![screenshot](/screenshot.png)

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
