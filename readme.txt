
Introduction
------------

The time-order project was created by Noah Healy as a way to securely
create a verifiable, unique iterator for any content. The end user
submits 3 items: 

- a checksum of their content

- desired type of iterator

- your public key


We add a unique iterator, and sign the package with our public key. 

The process happens on a very secure central server. The iterator is
both a unique order and a unique identifier.

Universal historical code
Universal historical container
Universal historical capsule

Maybe:

crypto verifiable historical stamp
crypto verifiable historical code



What is it
----------

This service offers global historical order verification of a
request. We call this a "universal historical code" or UHC because it
contains a unique integer which establishes the order of all UHCs. The
UHC contains a copy of of your request and the iterator. We attach the
public key used for the UHC signature. Your request consists of three
pieces of data: a signed checksum of your data, the public key of the
signature, and the type of the checksum. Since there is only one
source for the UHC iterator, you or any third party can verify the
historical order of any two data objects. Your original data is only
disclosed to verify the checksum, and you would only disclose your
data to a trusted party (such as a judge). It is not necessary to
disclose your data to verify the order of any two UHCs.

For example, you checksum and sign a video of innovative
technology. Your competitor also has a video. You get a UHC before
your competitor. (You have a lower iterator number.) You can verify
that your UHC preceded that of your competitor.



Technical
---------


The UHC server needs a public/private key pair. Clearly, the private
key must be maintained in very secure circumstances. The server also
has a persistent iterator.

After recieving a request, the server verifies that the signed
checksum matches and public key match the checksum type. The server
also verifies that the checksum type is presently thought to be
cyptographically sound. Next the server concatenates the full request
with the next iterator and signs the resulting object. The UHC object
and server public key are returned. You should keep both the public
key and the UHC.



Services offered
----------------

Create a time-order iterator

Verify a time order iterator, especially to confirm that some second
iterator is before/after your iterator.

