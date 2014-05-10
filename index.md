---
layout: page 
title: Nyms Identity Directory
image:
  feature: ant1.jpg
---

## 1. Introduction

Even though e-mail encryption software based on open standards such as S/MIME and OpenPGP has been widely available for the last 20 years email encryption is rarely used today. Users find email encryption difficult to use, especially dealing with key management.

Currently PGP public keys are distributed from public directories called key servers where keys can be published permanently by anybody.  When new keys are uploaded to key servers there is no attempt to verify that the email address or other name information in the uploaded key is valid, or even that another key under the same email address doesn't already exist.  If somebody publishes a false key under your name or email address there is nothing you can do to remove the malicious key since the system provides no way to delete published key information and no way to know who should have permission to remove false information.

The way that these problems are supposed to be resolved is with an authentication model called the Web of Trust where users sign keys of other users after verifying that they are who they say they are.  In theory, if some due diligence is applied in signing other people's keys and a sufficient number of people participate you'll be able to follow a short chain of signatures from people you already know and trust to new untrusted keys you download from a key server.  In practice this has never worked out very well as it burdens users with the task of manually finding people to sign their keys and even experts find the Web of Trust model difficult to reason about.

The Nyms Identity Directory is a replacement for all of this.  Keyservers are replaced with an identity directory that gives users full control over publication of their key information and web of trust is replaced with a distributed network of trusted notaries which validate user keys with an email verification protocol.

The system has been designed from the ground up to support the creation of messaging applications such as email clients which fully automate secure exchange of encrypted messages and only require users to make trust decisions in exceptional circumstances.  

This document provides an overview of the Nyms Identity Directory and describes various components of the system.  

The Nyms system notarizes user public keys with cryptographic signatures and also distributes these signed keys from a network of directory servers.  There are separate infrastructure components for each of these two functions which are described in the sections below on Certification and Directory infrastructure.

### 1.1 Terminology

**Identity Certificate**

A series of OpenPGP packets representing a set of public keys and addresses belonging to a single user identity.  In most descriptions of OpenPGP tools this is simply called a *Public Key* even though it generally consists of at least two public keys (signing + encryption), name information identifying the owner, and various other meta-data which is self-signed by a master signing key.  To remove ambiguity we use the name *Identity Certificate* for this construction and reserve the term *public key* for referring to a specific single asymmetric key.

**Directory Service**

A server which distributes **Identity Certificates** which have been endorsed by the **Trusted Notary** network.

The role of this service is similar to existing OpenPGP key servers, but it is designed to provide more privacy and control to users.

**Endorse / Certify**

Identity Certificates which are **certified** or **endorsed** by a **Trusted Notary** are signed with the certification key of the notary.  Both of the verbs *endorse* and *certify* are used interchangeably in this document.

**Trusted Notary**

Notaries in the **Nyms** system have two roles:

1. Endorsement of **Identity Certificates** by cryptographically signing them after verification of certificate address information with an automated protocol.
2. Distribute certificates from a **Directory Service**.

Trust is distributed across a network of multiple notary systems by configuring relying parties (i.e. client agents) to require endorsements from multiple notaries.


**Remote Verification**

Notaries verify address information such as email addresses by performing a verification protocol.  The email verification protocol is described later in this document.

**Participating Provider**

A service provider is called participating if they run infrastructure to endorse the certificates of their own users.  This may be preferable to remote verification since the provider itself is in the best position to verify the legitimacy of user addresses of their service.  

## 2. Certification Infrastructure

The certification infrastructure is responsible for performing endorsements that bind user addresses to OpenPGP public keys in an **Identity Certificate**.  In this system, some email providers may wish to participate directly by endorsing the keys of their own users.  We call these 'participating' providers and sometimes refer to all other providers as 'non-participating' to make the distinction.  Endorsement service is provided to users of non-participating email providers by performing a two-way email verification protocol to demonstrate that a user is control of an email address contained in an **Identity Certificate**.

The email verification system is called the Remote Verification Service.

Email providers who endorse keys for their own users run a similar component called a Provider Verification Service.

Both the Remote and Provider verification services use a second service called Certificate Endorsement Service to actually sign the keys.


### 2.1 Certificate Endorsement Service

![image](/images/certification_service.png "Certification Service")

The **Certificate Endorsement Service** runs on an isolated, hardened server and signs **Identity Certificates**.  The private signing key is (or should be) stored in a **Hardware Security Module**[^1], and all activity is logged for auditing in case a security incident needs to be investigated.  

Each **Trusted Notary** runs a service which signs certificates after verifying them by sending email to a UID address of the certificate.  This email verification service is called the **Remote Verification Service** and uses the **Certificate Endorsement Service** to actually sign the certificates.

Providers who sign the certificates of their own users (**participating providers**), also privately run a **Certificate Endorsement Service** which signs certificates upon request for only the email domain(s) of the provider.

In both applications, the same component is used but it is configured with a different signing policy in each case.

###2.2 Provider Verification Service

![image](/images/provider_verification.png "Provider Verification")

The **Provider Verification Service** is run by a **participating provider** to allow users to have their certificates endorsed.  This service would use the user authentication system of the service provider to verify the legitimacy of endorsement requests.

###2.3 Remote Verification Service

![image](/images/remote_verification.png "Remote Verification")


The Remote Verification Service is run by each of the notaries to provide the ability to endorse certificates for users of providers who do not participate directly in the system.  For Email this service performs a verification protocol by sending and receiving an email message from the email address identified in the certificate to be endorsed.

#### 2.3.1 Mail Verification Protocol

##### Step 1

	Client ==> Server  [email, pubkey]

The user initiates the protocol by sending a message containing an email address and an OpenPGP public key (**Identity Certificate**).  The public key must contain only a single UID which matches the email address specified in the request, and must have an encryption sub key which is properly self-signed.  If the certificate contains other UID or public keys, the client must omit these OpenPGP packets from the certificate presented in the request.

##### Step 2

	Server ==> Client [ ENCRYPT_user(challenge value) ]
	
Verification Service chooses a random challenge value, encrypts it under the encryption sub key provided by the user and transmits it over SMTP to the email address provided in the user request.

Since connections between MTAs are difficult to secure robustly with TLS[^2], we make some attempt to 'pin' security information about the connection to SMTP server of the user's provider when delivering this message.

If this is the first time the system has contacted the SMTP server for this provider some information is stored:

1. MX records
2. STARTTLS availability
3. Fingerprint of TLS certificate presented by SMTP server

If this is not the first time performing the verification protocol against this server, then the stored information for this provider is compared against the information collected during this run of the protocol.  An alert will be generated for investigation if any of this information has changed, but under the default operating policy this will not prevent the verification from successfully completed.

##### Step 3

	Client ==> Server [ E_kcs( SIGN_user(challenge value) ) ]
	

If the provider implements mail sender authentication, we use this information to confirm the authenticity of the message from the user to raise the difficulty of attacking the verification system.  As in Step 1, this information is stored and alerts are generated if anything changes unexpectedly.

* If the provider publishes a **Sender Policy Framework**[^3] record, the provider server sending the message is verified as authentic according to the published policy.

* If the provider implements **DomainKeys Identified Mail**[^4], the signature on the received message is verified.

* If a **DMARC**[^5] policy is published by the provider, it is consulted to confirm the configuration or presence of DKIM and/or SPF.

##### Step 4

	Server ==> Client [ pub key signed by certification service ]
	
If the verification completes successfully, the certificate is signed by the endorsement service and returned to the user.  Once the user has collected the required number of endorsements from the network, the certificate may be published by the user in the directory under the verified address.

### 2.4 Other Authentication



#### 2.4.1 OTR Keys

The directory supports managing OTR identity keys by adding the public key to the OpenPGP keyring of the user and certifying it under this system after verification with a similar protocol to the mail verification protocol performed over Jabber.

#### 2.4.2 Web Verification

We'll use Twitter in this example, but web verification could be adapted for various 
types of online accounts such as reddit, forums, linkedin, github, etc...

In this example the twitter user @nymsuser performs the following steps:

##### Step 1

User publishes master key fingerprint in a web accessible location.  In this case @nymsuser includes the fingerprint in a tweet

https://twitter.com/nymsuser/status/1234567

##### Step 2

Add User ID packet for this web account:

"twitter: @nymsuser"

##### Step 3

Record added in Step 2 is self-signed with master key

Add notation to self-signature containing URL from step 1:

urltype=twitter,url=https://twitter.com/nymsuser/status/1234567

##### Step 4

Optionally upload to directory service which will confirm that the web verification information is valid and then make key available for queries for this twitter user: @nymsuser.

##3. Directory Infrastructure

###3.1 Directory Service

When a user wants to obtain an authenticated public key for another user it contacts the directory service.  This service performs a function similar to existing OpenPGP key servers except that the keys it distributes have all been certified by the certification system described above.

Additionally the directory service provides some privacy features which prevent easily enumerating the entire database and allow users to control what is returned from queries.

### 3.2 Query Mix

The security of the directory network does not rely entirely on the integrity of the notary system.  There is also a basic expectation of continuity of keys.  Once a user has retrieved a key from the directory, the key will periodically be re-requested at random intervals both by the owner of the key as well as by anyone else who has previously retrieved the key.  Not only does this allow the key owner to update information such as an 'avatar' (stored as Image Attribute) and expiry information but also makes it possible for everybody to verify that keys published by the directory are not changing.

In order to strengthen the value of this verification, the directory server which answers a lookup query does not know the identity the requesting party.  To achieve this, the requesting user does not directly contact the server which will answer the request. Rather, the user selects a short random path (ie. 3 hops) through the available directory servers and constructs a Chaum Mix message (and response block) from the public keys of the servers on the path and transmits it to the first server on the path.

Preventing the final server from knowing the identity of the user performing the query means that a dishonest directory server cannot effectively distribute bad keys without detection since the server cannot guess if the user has previously requested this key.  Additionally, users are protected from leaking too much information about who they are communicating with based on the keys they are requesting.

###3.3 Key Revocation

Revocation of certified keys published in the directory is a difficult problem which must be handled correctly to ensure that stale useless keys do not accumulate and so that the system can accommodate users who lose access to their private keys.

By default, revocation is implemented by issuing certifications of a short duration (for example 30 days) which can be renewed at any time by the user after demonstrating possession of the private keys by signing a renewal message.

If a certified key expires without renewal the directory service records for the addresses belonging to this user are vacated so that the user can now re-register with a newly generated key.

Some users may not feel comfortable with the opportunity that this may create for an attacker to register false keys under their addresses if for some reason they are unable to renew keys in the required period.  For this reason, an option is provided for the user to request that their records be vacated and reset for re-registration only when a revocation certificate is presented.

#### 3.4 Key Segmentation

ID servers allow users to segment identity information so that different types of queries will only return information relevant to the particular query. A user may have both an email address and a jabber address under the same identity, but does not want to reveal their jabber address to somebody who queries for their email encryption keys. Another case would be a user who has multiple email addresses under the same identity, and some are more public than others.

#### 3.5 Key Obfuscation

## 4. Client Agent

Clients in the Nyms system have a lot of responsibilities compared to clients of the traditional OpenPGP key server network which simply make HKS queries to a key server.

1. Periodically download latest status document from notary network
2. Schedule requests for updates of certificates
3. Verify that certificates are correctly endorsed
4. Generate obfuscated lookup keys
5. Construct Query Mix messages
6. Renewing publication of certificates

Rather than require every messaging client to implement all of this behavior themselves, the client functionality of the system is provided in the form of a portable software agent which provides an inter-process API which applications can use to retrieve and manage certificates from the directory system.

### 4.1 Security Policy

Existing messaging applications such as E-Mail clients which include integrated PGP encryption functionality implement whatever ad-hoc strategy the author decided was the best plan for importing public keys, resolving conflicts, and determining which keys are trustworthy.



[^1]: http://en.wikipedia.org/wiki/Hardware_security_module
[^2]: http://blog.cryptographyengineering.com/2012/05/if-wishes-were-horses-then-beggars.html
[^3]: http://www.openspf.org/
[^4]: http://tools.ietf.org/html/rfc6376
[^5]: http://tools.ietf.org/html/draft-kucherawy-dmarc-base-04


