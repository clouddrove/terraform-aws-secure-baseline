'use strict';

/**
 * Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 */
const AWS = require('aws-sdk');
const url = require('url');
const https = require('https');

const webHookUrl = process.env['webHookUrl'];
const slackChannel = process.env.slackChannel;
const minSeverityLevel = process.env['minSeverityLevel'];

function postMessage(message, callback) {
    const body = JSON.stringify(message);
    const options = url.parse(webHookUrl);
    options.method = 'POST';
    options.headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
    };

    const postReq = https.request(options, (res) => {
        const chunks = [];
        res.setEncoding('utf8');
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
            if (callback) {
                callback({
                    body: chunks.join(''),
                    statusCode: res.statusCode,
                    statusMessage: res.statusMessage,
                });
            }
        });
    return res;
    });

    postReq.write(body);
    postReq.end();
}

function processEvent(event, callback) {
    const message = event;
    const consoleUrl = `https://console.aws.amazon.com/guardduty`;
    const finding = message.detail.type;
    const findingDescription = message.detail.description;
    const findingTime = message.detail.updatedAt;
    const findingTimeEpoch = Math.floor(new Date(findingTime) / 1000);
    const account =  message.detail.accountId;
    const region =  message.region;
    const messageId = message.detail.id;
    const lastSeen = `<!date^${findingTimeEpoch}^{date} at {time} | ${findingTime}>`;
    var color = '#7CD197';
    var severity = '';

    if (message.detail.severity < 4.0) {
        if (minSeverityLevel !== 'LOW') {
            callback(null);
            return;
        }
        severity = 'Low';
    } else if (message.detail.severity < 7.0) {
        if (minSeverityLevel === 'HIGH') {
            callback(null);
            return;
        }
        severity = 'Medium';
        color = '#e2d43b';
    } else {
        severity = 'High';
        color = '#ad0614';
    }

    const attachment = [{
              "fallback": finding + ` - ${consoleUrl}/home?region=` +
        `${region}#/findings?search=id%3D${messageId}`,
        "pretext": `*Finding in ${region} for Acct: ${account}*`,
        "title": `${finding}`,
        "title_link": `${consoleUrl}/home?region=${region}#/findings?search=id%3D${messageId}`,
        "text": `${findingDescription}`,
        "fields": [
            {"title": "Severity","value": `${severity}`, "short": true},
            {"title": "Region","value": `${region}`,"short": true},
            {"title": "Last Seen","value": `${lastSeen}`, "short": true}
        ],
        "mrkdwn_in": ["pretext"],
        "color": color,
        "footer": "CloudDrove",
        "footer_icon": "https://clouddrove.com/media/images/favicon.ico"
        }];

    const slackMessage = {
        channel: slackChannel,
        text : '',
        attachments : attachment,
        username: 'GuardDuty',
        'mrkdwn': true,
        icon_url: 'https://raw.githubusercontent.com/aws-samples/amazon-guardduty-to-slack/master/images/gd_logo.png'
    };

    postMessage(slackMessage, (response) => {
        if (response.statusCode < 400) {
            console.info('Message posted successfully');
            callback(null);
        } else if (response.statusCode < 500) {
            console.error(`Error posting message to Slack API: ${response.statusCode} - ${response.statusMessage}`);
            callback(null);
        } else {
            callback(`Server error when processing message: ${response.statusCode} - ${response.statusMessage}`);
        }
    });
}

exports.handler = (event, context, callback) => {
        processEvent(event, callback);
};
