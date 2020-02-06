# Hyperledger Aries Key Management Service

Aries Key Management Service is the base layer for creating agents in Aries and storing secrets.
The storage layer is for any Aries backend like files and databases. It is up to the Agents to implement
the policies and roles surrounding permissions for accessing keys and other objects.

As more plugins are added, they can be chosen as features at compile time.