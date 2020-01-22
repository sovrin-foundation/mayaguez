# Hyperledger Aries Core

Aries Core is the base layer for creating agents in Aries.
The main features offered here are common APIs for a network layer and storage layer.
The storage layer is for any Aries backend like files and databases.
The network layer is for communicating to any system like a blockchain.
Aries offers a public interface that can be whatever protocol implementers prefer.
The default is HTTP.

As more plugins are added, they can be chosen as features at compile time.