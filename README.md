ntlmauth
========

NTLM Authentication implemented in Javascript for use with NodeJS. This library was created to support NTLM authentication for SQL Server connections, it's now being tested in a branch of Tedious. Funnily enough the authentication bits work pretty well - the actual TDS is broken, still investigating why. With this library you should be able to code NTLM authentication on top of other protocols.

You can use this library also to take a look at what the process of responding to an NTLM challenge looks like by setting the debug flag to true in the object you have created.

```
NTLMAuth = require('ntlmauth');
ntlmauth = new NTLMAuth;
ntlmauth.debug = true;
```

This code is experimental, and it comes with no assurance that it will do much more than crash and burn. Use it at your own risk.

Quick Intro
===========

If you want to take this library for a spin you start by adding it to your package.json as a requirement, then you can do something in the lines of:

1 - Prepare an initial request:

```
NTLMAuth = require('ntlmauth');
ntlmauth = new NTLMAuth;

var ntlmPacket = ntlmauth.createSSPIRequest('DomainName');
```

This step will create a packet you can send to a server to start the NTLM sequence. How you send the packet will depend on the protocol you are using. In TDS it will - for example be attached to a LOGIN7 request.

2 - Parse the server response

At this point some server will have sent you a challenge, you get the challenge packet and used it to prime the NTLMAuth object:

```
ntlmauth.parseChallenge(challengeBuffer);
```

3 - Generate the response

Once you parsed the challenge you can generate a response like so:

```
var responseBuffer = ntlmauth.createResponse('domain', 'username', 'password');
```

Now you can get this responseBuffer over to the server - again, in TDS you would send this response embedded in a NTLM Response type packet.

