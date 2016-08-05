# Entrance-Backend
The Entrance Backend consits of an Attribute Authority (AA) for Attribute-based Encryption,  an RESTlike User and Container API, an OrientDB


SETUP guidline:


How to initialize the config file:
	
	mvn compile
	mvn exec:java -Dexec.mainClass="rest.AttributeAuthorityServer" -Dexec.args="init"

The config.properties file enables changing options, such as the maximum number of users in the system, the attribute authority port number, the database options, etc. The description of each option can be seen in src/main/java/rest/ServerConfigDefaults.java.

How to run:
	
	mvn compile
	mvn exec:java -Dexec.mainClass="rest.AttributeAuthorityServer"

