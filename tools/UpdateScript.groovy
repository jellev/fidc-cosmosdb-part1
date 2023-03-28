/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */


import static groovyx.net.http.ContentType.JSON
import static groovyx.net.http.Method.GET
import static groovyx.net.http.Method.PUT

import org.identityconnectors.framework.common.exceptions.InvalidCredentialException
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException
import org.identityconnectors.framework.common.exceptions.UnknownUidException

import groovy.json.JsonBuilder
import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.Uid

def operation = operation as OperationType
def updateAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def name = id as String
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def uid = uid as Uid

log.info("Entering " + operation + " Script");

switch (operation) {
    case OperationType.UPDATE:
        def builder = new JsonBuilder()

        // Since we do a PUT we need all attributes first
        connection.request(GET, JSON) { req ->
            uri.path = '/admin/api/2020-10/customers/' + uid.uidValue + '.json'

            response.success = { resp, json ->
                assert resp.status == 200

                builder {
                    customer {
                        'id' json.customer.id            
                        userName(updateAttributes.hasAttribute("emailAddress") ? updateAttributes.findString("emailAddress") : json.customer.email)
                        phone(updateAttributes.hasAttribute("telephoneNumber") ? updateAttributes.findString("telephoneNumber") : json.customer.phone)
                        email(updateAttributes.hasAttribute("emailAddress") ? updateAttributes.findString("emailAddress") : json.customer.email)
                        last_name(updateAttributes.hasAttribute("familyName") ? updateAttributes.findString("familyName") : json.customer.last_name)
                        first_name(updateAttributes.hasAttribute("givenName") ? updateAttributes.findString("givenName") : json.customer.first_name)
                        total_spent(updateAttributes.hasAttribute("totalspent") ? updateAttributes.findString("totalspent") : json.customer.total_spent)
                        accepts_marketing(updateAttributes.hasAttribute("marketing") ? updateAttributes.findBoolean("marketing") : json.customer.accepts_marketing)
                        note(updateAttributes.hasAttribute("note") ? updateAttributes.findString("note") : json.customer.note)
                    }
                }
            }

            response.failure = { resp, json ->
                assert resp.status >= 400
                switch (resp.status) {
                    case 401 :
                        throw new InvalidCredentialException()
                    case 403 :
                        throw new PermissionDeniedException()
                    case 404 :
                        throw new UnknownUidException("Entry not found")
                    default :
                        throw new ConnectorException("Get Failed")
                }
            }
        }

        connection.request(PUT, JSON) { req ->
            uri.path = '/admin/api/2020-10/customers/' + uid.uidValue + '.json'
            body = builder.toString()
            headers.'If-Match' = "*"

            response.success = { resp, json ->
                log.info("Update successful");
                log.error("RESPONSE: " + json);
            }

            response.failure = { resp, json ->
                log.info("Update failed")
            }
        }
        break
    case OperationType.ADD_ATTRIBUTE_VALUES:
        throw new UnsupportedOperationException(operation.name() + " operation of type:" +
                objectClass.objectClassValue + " is not supported.")
    case OperationType.REMOVE_ATTRIBUTE_VALUES:
        throw new UnsupportedOperationException(operation.name() + " operation of type:" +
                objectClass.objectClassValue + " is not supported.")
    default:
        throw new ConnectorException("UpdateScript can not handle operation:" + operation.name())
}

return uid