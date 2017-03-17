# Entrance-Backend
The Entrance Backend consits of an Attribute Authority (AA) for Attribute-based Encryption, an RESTlike User and Container API, an OrientDB. We implemented the ABE scheme  "Practical Attribute-Based Encryption: Traitor Tracing, Revocation, and Large Universe" (https://eprint.iacr.org/2014/616).


### SETUP guideline:

How to initialize the config file:
	
	mvn compile
	mvn exec:java -Dexec.mainClass="rest.AttributeAuthorityServer" -Dexec.args="init"

The config.properties file enables changing options, such as the maximum number of users in the system, the attribute authority port number, the database options, etc. The description of each option can be seen in src/main/java/rest/ServerConfigDefaults.java.

How to run:
	
	mvn compile
	mvn exec:java -Dexec.mainClass="rest.AttributeAuthorityServer"

### API description:
***RESTlike calls:***

* Use the same user id as umAPI to refer to users. it will be internally mapped to the position in the matrix

<pre><code>void createNewUser(int uid);</code></pre>

`POST` /user/

* Retrieves the base private key of the user if it exists 
<pre><code> JSON getUserBasePrivateKey(int uid);</code></pre>

`GET` /user/<uid>

* Deletes the user record

<pre><code>JSON deleteUserFromRecord(int uid);</code></pre>

`DELETE` /user/<uid>

* Asks if the AA already created an attribute key for user. If the answer is not, then the creation will be triggered asynchronously.

<pre><code> boolean createAttributeForUser(String attribute, int uid);</code></pre>

`PUT` /user/<uid>/attribute/<attribute>

* Retrieves the private key component (attribute secret key) of the user if it exists

<pre><code> JSON getAttributeForUser(int uid, String attribute);</code></pre>

`GET` /user/<uid>/attribute/<attribute>

* Revokes an attribute from a user. This also adds this attribute to a revocation list to actively revoke this through DHT and other means.

<pre><code> boolean revoke(String attribute, int uid);</code></pre>

`DELETE` /user/<uid>/attribute/<attribute>

* List of currently tracked files (only id of file)
// TODO: is it really necessary?

<pre><code> List<int> getFileList();</code></pre>

`GET` /encrypt/

* Encrypts the data read from the input file using the given policy, and writes the encrypted data into the specified file.

<pre><code> JSON encrypt(JSONObject reducedManifest);</code></pre>

`POST` /encrypt/<cid>

* Get file info
<pre><code> JSON getFileInfo(int cid);</code></pre>

`GET` /encrypt/<cid>

* Delete file (tracking) and return success status
<pre><code> boolean deleteContainer(int id);</code></pre>

`DELETE` /encrypt/<cid>

* Decrypts the data read from the input container and writes it into the specified output directory. This call blocks, shouldn't block in a later development step. <cid> can be any number and is currently disregarded, because decryption is stateless and blocking.

<pre><code> JSON decrypt(JSONObject reducedManifest);</code></pre>
`POST` /decrypt/<cid>

* Get file info: currently not implemented, because decryption is currently a stateless and blocking operation 
// TODO: is it really necessary?

<pre><code> JSON getFileInfo(int cid);</code></pre>

`GET` /decrypt/<cid>

* Gets an array containing the info of the authority like type, address and authentication type.
<pre><code> JSON getAuthorityInfo();</code></pre>
`GET` /authority/info



* Reduced manifest for single authority (see up-to-date version in src/main/resources/encryptionManifest.schema.json):
```json
{
  "title": "Encryption job description",
  "type": "object",
  "properties": {
    "files": {
      "title": "files",
      "type": "array",
      "minItems": 1,
      "items": {
        "title": "file",
        "type": "object",
        "properties": {
          "path": {
            "description": "Paths to files that need to be encrypted",
            "anyOf": [
              { "type": "string", "minLength": 1 },
              { "type": "array", "items": { "type": "string", "minLength": 1 }, "minItems": 1 }
            ]
          },
          "policy": {
            "description": "Optional policy string when encrypted with ABE (non-processed: numerical attributes are not expanded)",
            "type": "string",
            "minLength": 1
          },
          "type": {
            "decryption": "Encryption type",
            "type": "string",
            "minLength": 1
          },
          "expire": {
            "type": "array",
            "minItems": 1,
            "items": {
              "title": "time span",
              "type": "object",
              "properties": {
                "span": {
                  "type": "array",
                  "minItems": 1,
                  "maxItems": 2,
                  "items": { "type": "integer" }
                },
                "timezone": { "type": "string" },
                "strict": { "type": "boolean" }
              },
              "required": [ "span" ]
            }
          },
          "revoked": {
            "title": "Revoked users",
            "description": "List of revoked users which cannot decrypt this especially if their attribute set would satisfy the policy",
            "type": "object",
            "properties": {
              "users": {
                "title": "user array",
                "type": "array",
                "items": {
                  "type": "string",
                  "minLength": 1
                }
              },
              "usersType": {
                "title": "Array item type",
                "description": "Determines how the strings in the users array should be interpreted (Example: \"num10\" for numeric user ID in base 10 notation). This greatly depends on the implemented scheme.",
                "type": "string",
                "minLength": 1
              }
            },
            "required": [ "users", "usersType" ]
          }
        },
        "required": [ "path", "type" ]
      }
    },
    "outfile": {
      "title": "Output file path",
      "type": "string",
      "minLength": 1
    },
    "overwriteOutfile": {
      "title": "Overwrite flag for output file path",
      "type": "boolean"
    },
    "description": {
      "title": "Description of the container content",
      "type": "string"
    },
    "hidePolicy": {
      "title": "Hides the policy string in the final container (default: false)",
      "type": "boolean"
    },
    "owner": {
      "title": "Data owner information for the container in case somebody wants some contact information (everything is optional)",
      "type": "object",
      "properties": {
        "id": { "type": "string", "minLength": 1 },
        "name": { "type": "string", "minLength": 1 },
        "emails": {
          "title": "E-Mail addresses of the owner",
          "type": "array",
          "items": { "type": "string", "minLength": 1 },
          "minItems": 1
        },
        "urls": {
          "title": "URLs of the owner",
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "value": { "type": "string", "minLength": 1 },
              "type": { "type": "string", "minLength": 1 }
            },
            "required": [ "value", "type" ]
          },
          "minItems": 1
        }
      }
    }
  },
  "required": [ "files", "outfile" ]
}
```

# Example:
```json
{
    "files": [
        {
            "path": "/home/student/pictures_990x742/monkey_990x742.jpg",
            "type": "PABE14",
            "policy": "animallover",
            "expire": [
                {
                    "span": [ 1442667311 ],
                    "timezone": "UTC+01:00"
                }
            ]
        },
        {
            "path": "/home/student/pictures_990x742/penguins-south-georgia-island_86370_990x742er.jpg",
            "type": "PABE14",
            "policy": "animallover",
            "revoked": {
                "users": [ "3", "5" ],
                "usersType": "num10"
            }
        }
    ],
    "outfile": "/home/student/container.media",
    "overwriteOutfile": false,
    "description": "animals",
    "hidePolicy": true,
    "owner": {
        "id": "234kjn34-233lif-345345",
        "name": "John McClane",
        "emails": [ "john@save-christmas.org", "john@nakatomi-plaza-heroes.biz" ],
        "urls": [
            { "type": "homepage", "value": "https://nakatomi-plaza-heroes.biz/" },
            { "type": "teacher at", "value": "http://self-made-bombs.edu/" }
        ]
    }
}
```

Information:

    - "span" determines one time interval as unix timestamps. Multiple time intervals can be provided in "expire".
        - If "span" consists of only one integer, that integer is assumed to be the start time with no end time.
        - If "span" consists of two integers, those determine the access interval
    - If no "timezone" is provided, the Unix Epoch is assumed to be according to local time.
        - The contents should be fully qualified locales such as "Europe/Berlin" or "Asia/Jakarta"
        - CURRENTLY NOT USED: it is assumed that received times correspond to the server's timezone
    - Optional: files/expire, files/expire/timezone, files/revoked, overwriteOutfile, description, hidePolicy, owner, owner/id, owner/name, owner/emails, owner/urls


How to get a local address for direct ABE or AES endpoint?
- Let the admin enable dyn-dns or something like that and let the attribute authority know this configuration.


`getAttributeForUser` Return Type:
```json
{
    "component": "<some base64 encoded user attribute component>",
    "name": "att1",
    "external": false,
    "existed": true,
    "success": true
}
```
if result.existed and not result.success: "serialization error"
if result.external: "'component' doesn't exist, because it is provided by other means (DHT)"


`createAttributeForUser` Return Type:
```json
{
    "existed": true,
    "success": true
}
```

`getFileInfo` Return SCHEMA:
```json
{
    "title": "Container File Info",
    "type": "object",
    "properties": {
        "success": {
            "description": "request success",
            "type": "boolean"
        },
        "msg": {
            "description": "Error message when 'success' is false",
            "type": "string"
        },
        "status": {
            "description": "Container status (when 'success' is true)",
            "enum": [ "success", "failed", "processing" ]
        },
        "failMsg": {
            "description": "Error message when 'status' is 'failed'",
            "type": "string"
        }
    },
    "required": [ "success" ]
}
```
`encrypt` Return SCHEMA:
```json
{
    "title": "Container Encryption Schedule Result",
    "type": "object",
    "properties": {
        "success": {
            "description": "request success: Encryption triggered",
            "type": "boolean"
        },
        "msg": {
            "description": "Error message when 'success' is false",
            "type": "string"
        }
    },
    "required": [ "success" ]
}
```
