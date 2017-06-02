/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

var MongoClient = require('mongodb').MongoClient
    , assert = require('assert');

// Connection URL
const MONGO_URL = "mongodb://viyamamo:WildConstipatedGiraffe0518!@hopelabcluster-shard-00-00-x2eo0.mongodb.net:27017,hopelabcluster-shard-00-01-x2eo0.mongodb.net:27017,hopelabcluster-shard-00-02-x2eo0.mongodb.net:27017/hopelab?ssl=true&replicaSet=HopeLabCluster-shard-0&authSource=admin"
// Use connect method to connect to the server
MongoClient.connect(MONGO_URL, function (err, db) {
    assert.equal(null, err);
    console.log("Connected successfully to server");

    db.close();
});

const initialChatId = "introchat_001_A";
const menuInitialChatName = "menu_initial";
const CUSTOM_RETURN_TARGET = "USER_RETURN_CHAT_NAME";

const
    bodyParser = require('body-parser'),
    config = require('./config'),
    crypto = require('crypto'),
    express = require('express'),
    https = require('https'),
    request = require('request');

var app = express();
app.set('port', process.env.PORT || 8081);
app.set('view engine', 'ejs');
app.use(bodyParser.json({verify: verifyRequestSignature}));
app.use(express.static('public'));


if (!String.prototype.format) {
    String.prototype.format = function () {
        var args = arguments;
        return this.replace(/{(\d+)}/g, function (match, number) {
            return typeof args[number] != 'undefined'
                ? args[number]
                : match
                ;
        });
    };
}

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
    process.env.MESSENGER_APP_SECRET :
    config.appSecret

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
    (process.env.MESSENGER_VALIDATION_TOKEN) :
    config.validationToken;

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
    (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
    config.pageAccessToken;

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
    (process.env.SERVER_URL) :
    config.serverURL

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
    console.error("Missing config values");
    process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/webhook', function (req, res) {
    if (req.query['hub.mode'] === 'subscribe' &&
        req.query['hub.verify_token'] === VALIDATION_TOKEN) {
        console.log("Validating webhook");
        res.status(200).send(req.query['hub.challenge']);
    } else {
        console.error("Failed validation. Make sure the validation tokens match.");
        res.sendStatus(403);
    }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
    var data = req.body;

    // Make sure this is a page subscription
    if (data.object == 'page') {
        // Iterate over each entry
        // There may be multiple if batched
        data.entry.forEach(function (pageEntry) {
            var pageID = pageEntry.id;
            var timeOfEvent = pageEntry.time;

            // Iterate over each messaging event
            pageEntry.messaging.forEach(function (messagingEvent) {
                if (messagingEvent.optin) {
                    receivedAuthentication(messagingEvent);
                } else if (messagingEvent.message) {
                    receivedMessage(messagingEvent);
                } else if (messagingEvent.delivery) {
                    receivedDeliveryConfirmation(messagingEvent);
                } else if (messagingEvent.postback) {
                    receivedPostback(messagingEvent);
                } else if (messagingEvent.read) {
                    receivedMessageRead(messagingEvent);
                } else if (messagingEvent.account_linking) {
                    receivedAccountLink(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've
        // successfully received the callback. Otherwise, the request will time out.
        res.sendStatus(200);
    }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/authorize', function (req, res) {
    var accountLinkingToken = req.query.account_linking_token;
    var redirectURI = req.query.redirect_uri;

    // Authorization Code should be generated per user by the developer. This will
    // be passed to the Account Linking callback.
    var authCode = "1234567890";

    // Redirect users to this URI on successful login
    var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

    res.render('authorize', {
        accountLinkingToken: accountLinkingToken,
        redirectURI: redirectURI,
        redirectURISuccess: redirectURISuccess
    });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
    var signature = req.headers["x-hub-signature"];
    if (!signature) {
        // For testing, let's log an error. In production, you should throw an
        // error.
        console.error("Couldn't validate the signature.");
    } else {
        var elements = signature.split('=');
        var method = elements[0];
        var signatureHash = elements[1];

        var expectedHash = crypto.createHmac('sha1', APP_SECRET)
            .update(buf)
            .digest('hex');

        if (signatureHash != expectedHash) {
            throw new Error("Couldn't validate the request signature.");
        }
    }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfAuth = event.timestamp;

    // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
    // The developer can set this to an arbitrary value to associate the
    // authentication callback with the 'Send to Messenger' click event. This is
    // a way to do account linking when the user clicks the 'Send to Messenger'
    // plugin.
    var passThroughParam = event.optin.ref;

    console.log("Received authentication for user %d and page %d with pass " +
        "through param '%s' at %d", senderID, recipientID, passThroughParam,
        timeOfAuth);

    // When an authentication is received, we'll send a message back to the sender
    // to let them know it was successful.
    sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfMessage = event.timestamp;
    var message = event.message;

    console.log("Received message for user %d and page %d at %d with message:",
        senderID, recipientID, timeOfMessage);
    console.log(JSON.stringify(message));

    var isEcho = message.is_echo;
    var messageId = message.mid;
    var appId = message.app_id;
    var metadata = message.metadata;

    // You may get a text or attachment but not both
    var messageText = message.text ? message.text.toLowerCase() : null;
    var messageAttachments = message.attachments;
    var quickReply = message.quick_reply;

    var recipientInfo;

    if (!isEcho) {
        getUserInfo(senderID, function (response) {
            recipientInfo = JSON.parse(response);
        });
    }

    if (isEcho) {
        // Just logging message echoes to console
        console.log("Received echo for message %s and app %d with metadata %s",
            messageId, appId, metadata);
        return;
    } else if (quickReply) {
        var quickReplyPayload = quickReply.payload;
        console.log("Quick reply for message %s with payload %s",
            messageId, quickReplyPayload);
        getUserInfo(senderID, function (response) {
            recipientInfo = JSON.parse(response);
            console.log("Handling quick reply");
            console.log(recipientInfo);
            handleTrigger(quickReplyPayload, senderID, recipientInfo);
        });

        return;
    }

    getUserInfo(senderID, function (response) {
        recipientInfo = JSON.parse(response);
        if (messageText) {
            if (messageText.substring(0, 1) === '*') {
                sendTextMessage(senderID, "*Noted, thanks for the feedback!");
                return;
            }
            switch (messageText) {
                case 'name':
                    sendTextMessage(senderID, "Your name is " + recipientInfo.first_name + ".");
                    break;
                case 'menu':
                    openMenu(senderID, recipientInfo);
                    break;
                default:
                    console.log("Handling any text");
                    console.log(recipientInfo);
                    handleTrigger("any-text", senderID, recipientInfo);
            }
        } else if (messageAttachments) {
            sendTextMessage(senderID, "Message with attachment received");
        }
    });
}


/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function (messageID) {
            console.log("Received delivery confirmation for message ID: %s",
                messageID);
        });
    }

    console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    console.log("Received postback for user %d and page %d with payload '%s' " +
        "at %d", senderID, recipientID, payload, timeOfPostback);

    // When a postback is called, we'll send a message back to the sender to
    // let them know it was successful
    sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
    var senderID = event.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    console.log("Received message read event for watermark %d and sequence " +
        "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    console.log("Received account link event with for user %d with status %s " +
        "and auth code %s ", senderID, status, authCode);
}

/*
 * Sends Actions like typing_on bubble
 *
 */
function sendSenderAction(recipientId, senderAction) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        sender_action: senderAction
    };

    callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}

function openMenu(recipientId, recipientInfo) {
    console.log("**** Begin Open Menu ****");
    MongoClient.connect(MONGO_URL, function (err, db) {
        updateUserChatState(menuInitialChatName, db, recipientId, recipientInfo);
    });
}

function handleTrigger(trigger, recipientId, recipientInfo) {
    console.log("**** Begin Handle Trigger ****");
    MongoClient.connect(MONGO_URL, function (err, db) {
        processTrigger(trigger, db, recipientId, recipientInfo);
    });
}

function processTrigger(trigger, db, recipientId, recipientInfo) {
    console.log("Process trigger");
    db.collection('users').find({psid: recipientId}).toArray(function (err, users) {
        if (!users || users.length === 0) {
            //if there is no such user, initialize the user
            initiateChat(db, recipientId, recipientInfo);
        } else {
            findCurrentChatForUser(users[0], trigger, db, recipientId, recipientInfo);
        }
    });
}

function findCurrentChatForUser(user, trigger, db, recipientId, recipientInfo) {
    console.log("Find Current Chat For user, chatname: " + user.currentChatName);
    db.collection('chatscripts').find({name: user.currentChatName}).toArray(function (err, chats) {
        if (!chats || chats.length === 0) {
            //if the user's current state points to a non-existent chat, restart their chat
            initiateChat(db, recipientId, recipientInfo);
        } else {
            findNextChatForUser(chats[0], user.returnChatName, trigger, db, recipientId, recipientInfo);
        }
    });
}

function findNextChatForUser(chat, returnChatName, trigger, db, recipientId, recipientInfo) {
    console.log("FindNextChatForUser, transition: " + trigger);
    var nextChatName = null;
    var nextChatType = null;
    var pauseTimeInSeconds = 2;
    for (var i = 0; i < chat.transitions.length; i++) {
        if (chat.transitions[i].signal == trigger) {
            nextChatName = chat.transitions[i].target;
            nextChatType = chat.transitions[i].targetType;
            break;
        }
    }
    if (nextChatType && nextChatType === "module") {
        processChatModule(nextChatName, db, recipientId, recipientInfo, pauseTimeInSeconds);
    }
    else if (nextChatName) {
        processChatMessage(nextChatName, returnChatName, db, recipientId, recipientInfo, pauseTimeInSeconds);
    } else {
        console.log("Closing DB");
        db.close();
    }
}

function processChatModule(nextModuleName, db, recipientId, recipientInfo, pauseTime) {
    console.log("Process Chat Message for module: " + nextModuleName);
    db.collection('chatscripts').find({moduleName: nextModuleName}).toArray(function (err, chats) {
        if (!chats || chats.length === 0) {
            //if the user's chat transition points to a non-existent chat, do nothing
            //initiateChat(db, recipientId, recipientInfo);
        } else {
            var chat = chats[Math.floor(Math.random() * chats.length)];
            console.log("Target chat: " + chat.name);
            if (pauseTime && pauseTime > 0) {
                sendSenderAction(recipientId, "typing_on");
                setTimeout(function () {
                    sendMessageContent(chat.message, chat.name, db, recipientId, recipientInfo, chat.returnTarget);
                }, pauseTime * 1000);

            } else {
                sendMessageContent(chat.message, chat.name, db, recipientId, recipientInfo, chat.returnTarget);
            }
        }
    });
}

function processChatMessage(chatName, returnChatName, db, recipientId, recipientInfo, pauseTime) {
    console.log("Process Chat Message for chat: " + chatName);
    var targetChatName = (chatName === CUSTOM_RETURN_TARGET) ? returnChatName : chatName;
    console.log("Target chat: " + chatName);
    db.collection('chatscripts').find({name: targetChatName}).toArray(function (err, chats) {
        if (!chats || chats.length === 0) {
            //if the user's chat transition points to a non-existent chat, do nothing
            //initiateChat(db, recipientId, recipientInfo);
        } else {
            if (pauseTime && pauseTime > 0) {
                sendSenderAction(recipientId, "typing_on");
                setTimeout(function () {
                    sendMessageContent(chats[0].message, targetChatName, db, recipientId, recipientInfo, chats[0].returnTarget);
                }, pauseTime * 1000);

            } else {
                sendMessageContent(chats[0].message, targetChatName, db, recipientId, recipientInfo, chats[0].returnTarget);
            }
        }
    });
}

function updateUserChatState(chatName, db, recipientId, recipientInfo, chatReturnTarget) {
    console.log("Update User Chat State to " + chatName);
    var updatedUserInformation = {
        currentChatName: chatName,
        firstName: recipientInfo.first_name,
        lastName: recipientInfo.last_name
    };

    if (chatReturnTarget) {
        updatedUserInformation.returnChatName = chatReturnTarget;
    }

    if (db) {
        db.collection('users').updateOne(
            {psid: recipientId},
            {
                $set: updatedUserInformation
            },
            {upsert: true}
        ).then(function () {
            processTrigger("auto", db, recipientId, recipientInfo);
        });
    }
}


function initiateChat(db, recipientId, recipientInfo) {
    console.log("Initiate Chat");
    processChatMessage(initialChatId, initialChatId, db, recipientId, recipientInfo);
}

function sendMessageContent(messageContent, chatName, db, recipientId, recipientInfo, returnToChat) {
    console.log("Send message content");
    console.log(messageContent);
    if (messageContent.text) {
        messageContent.text = messageContent.text.split('{first_name}').join(recipientInfo.first_name);
    }
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: messageContent
    }

    callSendAPI(messageData, chatName, db, recipientId, recipientInfo, returnToChat);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData, chatName, db, recipientID, recipientInfo, returnToChat) {
    request({
        uri: 'https://graph.facebook.com/v2.6/me/messages',
        qs: {access_token: PAGE_ACCESS_TOKEN},
        method: 'POST',
        json: messageData

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            var recipientId = body.recipient_id;
            var messageId = body.message_id;

            if (messageId) {
                console.log("Successfully sent message with id %s to recipient %s",
                    messageId, recipientId);
            } else {
                console.log("Successfully called Send API for recipient %s",
                    recipientId);
            }

            if (chatName) {
                updateUserChatState(chatName, db, recipientID, recipientInfo, returnToChat);
            }
        } else {
            console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

function getUserInfo(psid, callback) {
    request({
        uri: 'https://graph.facebook.com/v2.6/' + psid + '?access_token=' + PAGE_ACCESS_TOKEN,
        method: 'GET'

    }, function (error, response, body) {
        if (!error && response.statusCode == 200) {
            callback(body);
        } else {
            console.error("Failed calling User Info API", response.statusCode, response.statusMessage, body.error);
        }
    });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function () {
    console.log('Node app is running on port', app.get('port'));
});

module.exports = app;