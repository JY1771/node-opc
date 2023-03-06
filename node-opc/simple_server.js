#!/usr/bin / env node
/* eslint-disable max-statements */
/* eslint no-process-exit: 0 */
"use strict";
const path = require("path");
const fs = require("fs");
const os = require("os");
const assert = require("assert");
const chalk = require("chalk");
const yargs = require("yargs/yargs");
const envPaths = require("env-paths");



const mysql = require('mysql'); // mysql 변수에 mysql 모듈을 할당
const connection = mysql. createConnection({  //커넥션변수에 mysql변수에 있는 크리에이드커넥션 메소드를 호출(객체를 받음) 할당
    host    : '127.0.0.1',   //host객체 - 마리아DB가 존재하는 서버의 주소
    user    : 'root', //user객체 - 마리아DB의 계정
    password    : 'lsis6535',   //password객체 - 마리아DB 계정의 비밀번호
    database    : 'wind_power'   //database객체 - 접속 후 사용할 DB명
});

connection.connect();   // (위에 선언한 객체들을 가진)커넥션변수의 connect() 메소드를 호출하면 DB에 접속이 됨



const {
    OPCUAServer,
    OPCUACertificateManager,
    DataType,
    makeApplicationUrn,
    nodesets,
    RegisterServerMethod,
    extractFullyQualifiedDomainName,
    makeRoles,
    WellKnownRoles,
    Variant,
    StatusCodes,
} = require("node-opcua");

const {
    install_optional_cpu_and_memory_usage_node,
} = require("node-opcua-vendor-diagnostic");

const {
    build_address_space_for_conformance_testing,
}= require("node-opcua-address-space-for-conformance-testing");
const { result } = require("underscore");

Error.stackTraceLimit = Infinity;

const argv = yargs(process.argv)
    .wrap(132)

    .string("alternateHostname")
    .describe("alternateHostname")

    .number("port")
    .default("port", 26543)

    .number("maxSessions")
    .describe("maxSessions", "the maximum number of concurrent client session that the server will accept")
    .default("maxSessions", 500)

    .number("maxSubscriptionsPerSession")
    .describe("maxSubscriptionsPerSession", "the maximum number of concurrent subscriptions per session")

    .boolean("silent")
    .default("silent", false)
    .describe("silent", "no trace")

    .string("alternateHostname")
    .default("alternateHostname", null)

    .number("keySize")
    .describe("keySize", "certificate keySize [1024|2048|3072|4096]")
    .default("keySize", 2048)
    .alias("k", "keySize")

    .string("applicationName")
    .describe("applicationName", "the application name")
    .default("applicationName", "NodeOPCUA-Server")

    .alias("a", "alternateHostname")
    .alias("m", "maxSessions")
    .alias("n", "applicationName")
    .alias("p", "port")

    .help(true).argv;

const port = argv.port;
const maxSessions = argv.maxSessions;
const maxConnectionsPerEndpoint = maxSessions;
const maxSubscriptionsPerSession = argv.maxSubscriptionsPerSession || 50;

async function getIpAddresses() {
    const ipAddresses = [];
    const interfaces = os.networkInterfaces();
    Object.keys(interfaces).forEach(function (interfaceName) {
        let alias = 0;

        interfaces[interfaceName].forEach(function (iface) {
            if ("IPv4" !== iface.family || iface.internal !== false) {
                // skip over internal (i.e. 127.0.0.1) and non-ipv4 addresses
                return;
            }
            if (alias >= 1) {
                // this single interface has multiple ipv4 addresses
                // console.log(interfaceName + ":" + alias, iface.address);
                ipAddresses.push(iface.address);
            } else {
                // this interface has only one ipv4 address
                // console.log(interfaceName, iface.address);
                ipAddresses.push(iface.address);
            }
            ++alias;
        });
    });
    return ipAddresses;
}

const users = [
    {
        username: "user1",
        password: "password1",
        role: makeRoles([WellKnownRoles.AuthenticatedUser, WellKnownRoles.ConfigureAdmin])
    },
    { username: "user2", password: "password2", role: makeRoles([WellKnownRoles.AuthenticatedUser, WellKnownRoles.Operator]) }
];

const userManager = {
    isValidUser(username, password) {
        const uIndex = users.findIndex((x) => x.username === username);
        if (uIndex < 0) {
            return false;
        }
        if (users[uIndex].password !== password) {
            return false;
        }
        return true;
    },
    getUserRoles(username) {
        const uIndex = users.findIndex((x) => x.username === username);
        if (uIndex < 0) {
            return [];
        }
        const userRole = users[uIndex].role;
        return userRole;
    }
};

const keySize = argv.keySize;

const productUri = argv.applicationName || "NodeOPCUASample-Simple-Server";

const paths = envPaths(productUri);

(async function main() {
    const fqdn = await extractFullyQualifiedDomainName();
    // console.log("FQDN = ", fqdn);

    const applicationUri = makeApplicationUrn(fqdn, productUri);
    // -----------------------------------------------
    const configFolder = paths.config;
    const pkiFolder = path.join(configFolder, "PKI");
    const userPkiFolder = path.join(configFolder, "UserPKI");

    const userCertificateManager = new OPCUACertificateManager({
        automaticallyAcceptUnknownCertificate: true,
        name: "UserPKI",
        rootFolder: userPkiFolder
    });
    await userCertificateManager.initialize();

    const serverCertificateManager = new OPCUACertificateManager({
        automaticallyAcceptUnknownCertificate: true,
        name: "PKI",
        rootFolder: pkiFolder
    });

    await serverCertificateManager.initialize();

    const certificateFile = path.join(pkiFolder, `server_certificate1.pem`);
    if (!fs.existsSync(certificateFile)) {
        // console.log("Creating self-signed certificate");

        await serverCertificateManager.createSelfSignedCertificate({
            applicationUri: applicationUri,
            dns: argv.alternateHostname ? [argv.alternateHostname, fqdn] : [fqdn],
            ip: await getIpAddresses(),
            outputFile: certificateFile,
            subject: "/CN=Sterfive/DC=Test",
            startDate: new Date(),
            validity: 365 * 10
        });
    }
    assert(fs.existsSync(certificateFile));
    // ------------------------------------------------------------------

    const server_options = {
        serverCertificateManager,
        certificateFile,

        userCertificateManager,

        port,

        maxConnectionsPerEndpoint: maxConnectionsPerEndpoint,

        nodeset_filename: [nodesets.standard, nodesets.di],

        serverInfo: {
            applicationName: { text: "NodeOPCUA", locale: "en" },
            applicationUri: applicationUri,
            gatewayServerUri: null,
            productUri: productUri,
            discoveryProfileUri: null,
            discoveryUrls: []
        },
        buildInfo: {
            buildNumber: "1234"
        },
        serverCapabilities: {
            maxSessions,
            maxSubscriptionsPerSession,
            maxSubscription: maxSessions * maxSubscriptionsPerSession,

            maxBrowseContinuationPoints: 10,
            maxHistoryContinuationPoints: 10,
            // maxInactiveLockTime
            operationLimits: {
                maxNodesPerRead: 1000,
                maxNodesPerWrite: 1000,
                maxNodesPerHistoryReadData: 100,
                maxNodesPerBrowse: 1000,
                maxNodesPerMethodCall: 200
            }
        },
        userManager: userManager,

        isAuditing: false,
        //xx registerServerMethod: RegisterServerMethod.HIDDEN,
        //xx registerServerMethod: RegisterServerMethod.MDNS,
        registerServerMethod: RegisterServerMethod.LDS,
        discoveryServerEndpointUrl: "opc.tcp://localhost:4840"
    };

    process.title = "Node OPCUA Server on port : " + server_options.port;
    server_options.alternateHostname = argv.alternateHostname;
    
    //1.서버 인스턴스화
    const server = new OPCUAServer(server_options);

  
    //2.서버 초기화
    await server.initialize();

    async function post_initialize() {
        //3. 서버 네임스페이스를 변수로 확장
        const addressSpace = server.engine.addressSpace;

        build_address_space_for_conformance_testing(addressSpace);

        install_optional_cpu_and_memory_usage_node(server);

        addressSpace.installAlarmsAndConditionsService();

        const turbineOriginTables = [];

        const rootFolder = addressSpace.findNode("RootFolder");
        assert(rootFolder.browseName.toString() === "Root");

        const namespace = addressSpace.getOwnNamespace();

        // const myDevices = namespace.addFolder(rootFolder.objects, { browseName: "MyDevices" });
        const IEC61400 = namespace.addFolder(rootFolder.objects, { browseName: "IEC61400" });
      
        const makeTurbineOriginTables = () => {
            connection.query('SELECT * FROM tb_turbine', function(error, results, fields){          
                if (error) {
                    console.log(error);
                    return null;
                } //에러에 값이 있다면 에러값을 콘솔에 출력

                
                if(results.length > 0){
                    for(let i=0; i<results.length; i++){
                        let o = namespace.addFolder(rootFolder.objects, { browseName: String(results[i].model) });                        
                        turbineOriginTables.push({"organized" : o , "data_table" : String(results[i].data_table), "dev_id" : results[i].dev_id});
                    }

                    makeTurbinOriginNodeList(turbineOriginTables);                    
                }
            });
        }

        await makeTurbineOriginTables();


        /*
         * letiation 0:
         * ------------
         *
         * Add a letiable in folder using a raw letiant.
         * Use this letiation when the letiable has to be read or written by the OPCUA clients
         */
        

        const makeUnifiledNodeList = async () => {
            connection.query('SELECT * FROM tb_unified_definition', function(error, results, fields){                
                if (error) {
                    console.log(error);
                    return null;
                } 
                
                if(results.length > 0){                    
                    for(let i=0; i<results.length; i++){                    
                        try {
                            let n = String(results[i].ln) + '-' +String(results[i].name);
                            let dt = results[i].attribute_name;
                            let _dataType = "Double";
                            let dataType = DataType.Double;
                            let defaultValue = 0;
                            
                            if(dt == "Boolean") {
                                _dataType = "Boolean";
                                dataType = DataType.Boolean;
                                defaultValue = false;
                            }

                            namespace.addVariable({
                                organizedBy: IEC61400,
                                browseName: n,
                                nodeId: "ns=1;s="+n,
                                dataType: _dataType,
                                // value: new Variant({ dataType: dataType, value: defaultValue })
                                value: {
                                    get: function () {
                                        return new Variant({dataType: dataType, value: defaultValue });
                                    },
                                    set: function (variant) {
                                        // variable2 = parseFloat(variant.value);
                                        console.log("Client SET Value nodeName : ",n+" / Value : "+variant.value);                                        
                                        return StatusCodes.Good;
                                    }
                                }
                            });
                        } catch (err) {
                            return err;
                        }                        
                    }
                   
                }
            });           
        }

        await makeUnifiledNodeList();


        const makeTurbinOriginNodeList = async (turbineOriginTables) => {

            for(let j=0; j<turbineOriginTables.length; j++){
                connection.query("SHOW COLUMNS FROM wind_power."+turbineOriginTables[j].data_table , async (error, results) => {
                   
                    if (error) {
                        console.log(error);
                        return null;
                    }       

                    if(results.length > 0){                        
                        for(let i=0; i<results.length; i++){                        
                            try {
                                let n = String(results[i].Field);                                
        
                                let dt = results[i].Type;
                                let _dataType = "Double";
                                let dataType = DataType.Double;
                                let defaultValue = 0;
                                
                                if(dt == "Boolean") {
                                    _dataType = "Boolean";
                                    dataType = DataType.Boolean;
                                    defaultValue = false;
                                }
                                
                                await namespace.addVariable({
                                    organizedBy: turbineOriginTables[j].organized,
                                    browseName: n,                                    
                                    nodeId: "ns=1;s=DEV"+turbineOriginTables[j].dev_id+"-"+n,
                                    dataType: _dataType,
                                    // value: new Variant({ dataType: dataType, value: defaultValue })
                                    value: {
                                        get: function () {
                                            return new Variant({dataType: dataType, value: defaultValue });
                                        },
                                        set: function (variant) {
                                            // variable2 = parseFloat(variant.value);
                                            console.log("Client SET Value nodeName : ",n+" / Value : "+variant.value);                                        
                                            return StatusCodes.Good;
                                        }
                                    }
                                });
                            } catch (err) {
                                return err;
                            }
                        }                       
                    }
                });
            }
        }

    }

    post_initialize();


    function dumpObject(node) {
        function w(str, width) {
            return ("" + str).padEnd(width).substring(0, width);
        }
        return Object.entries(node)
            .map((key, value) => "      " + w(key, 30) + "  : " + (value === null ? null : value.toString()))
            .join("\n");
    }

    // console.log(chalk.yellow("  server PID          :"), process.pid);
    // console.log(chalk.yellow("  silent              :"), argv.silent);

    await server.start();

    // console.log(chalk.yellow("\nregistering server to :") + server.discoveryServerEndpointUrl);

    const endpointUrl = server.getEndpointUrl();

    // console.log(chalk.yellow("  server on port      :"), server.endpoints[0].port.toString());
    // console.log(chalk.yellow("  endpointUrl         :"), endpointUrl);

    // console.log(chalk.yellow("  serverInfo          :"));
    // console.log(dumpObject(server.serverInfo));
    // console.log(chalk.yellow("  buildInfo           :"));
    // console.log(dumpObject(server.engine.buildInfo));

    // console.log(chalk.yellow("  Certificate rejected folder "), server.serverCertificateManager.rejectedFolder);
    // console.log(chalk.yellow("  Certificate trusted folder  "), server.serverCertificateManager.trustedFolder);
    // console.log(chalk.yellow("  Server private key          "), server.serverCertificateManager.privateKey);
    // console.log(chalk.yellow("  Server public key           "), server.certificateFile);
    // console.log(chalk.yellow("  X509 User rejected folder   "), server.userCertificateManager.trustedFolder);
    // console.log(chalk.yellow("  X509 User trusted folder    "), server.userCertificateManager.rejectedFolder);

    // console.log(chalk.yellow("\n  server now waiting for connections. CTRL+C to stop"));

    if (argv.silent) {
        console.log(" silent");
        console.log = function () {
            /** */
        };
    }
    //  console.log = function(){};

    server.on("create_session", function (session) {
        console.log(" SESSION CREATED");
        // console.log(chalk.cyan("    client application URI: "), session.clientDescription.applicationUri);
        // console.log(chalk.cyan("        client product URI: "), session.clientDescription.productUri);
        // console.log(chalk.cyan("   client application name: "), session.clientDescription.applicationName.toString());
        // console.log(chalk.cyan("   client application type: "), session.clientDescription.applicationType.toString());
        // console.log(chalk.cyan("              session name: "), session.sessionName ? session.sessionName.toString() : "<null>");
        // console.log(chalk.cyan("           session timeout: "), session.sessionTimeout);
        // console.log(chalk.cyan("                session id: "), session.sessionId);
    });

    server.on("session_closed", function (session, reason) {
        console.log(" SESSION CLOSED :", reason);
        // console.log(chalk.cyan("              session name: "), session.sessionName ? session.sessionName.toString() : "<null>");
        connection.end();
    });

    function w(s, w) {
        return (" " + s).padStart(w, "0");
    }
    function t(d) {
        return w(d.getHours(), 2) + ":" + w(d.getMinutes(), 2) + ":" + w(d.getSeconds(), 2) + ":" + w(d.getMilliseconds(), 3);
    }
    function indent(str, nb) {
        const spacer = "                                             ".slice(0, nb);
        return str
            .split("\n")
            .map(function (s) {
                return spacer + s;
            })
            .join("\n");
    }
    function isIn(obj, arr) {
        try {
            return arr.findIndex((a) => a === obj.constructor.name.replace(/Response|Request/, "")) >= 0;
        } catch (err) {
            return true;
        }
    }

    const servicesToTrace = ["CreateMonitoredItems", "Publish", "ModifyMonitoredItems"]; // "Publish", "TransferSubscriptions", "Republish", "CreateSubscription", "CreateMonitoredItems"];
    server.on("response", function (response) {
        if (argv.silent) {
            return;
        }
        if (isIn(response, servicesToTrace)) {
            console.log("%*%*%*%*%*%*%* response %*%*%*%*%*%*%*");
            console.log(                
                t(response.responseHeader.timestamp),
                response.responseHeader.requestHandle,
                response.schema.name.padEnd(30, " "),
                " status = ",
                response.responseHeader.serviceResult.toString()
            );
            console.log(response.constructor.name, response.toString());
        }
    });

    server.on("request", function (request, channel) {
        if (argv.silent) {
            return;
        }
        if (isIn(request, servicesToTrace)) {
            console.log("!@!@!@!@!@!@!@ request !@!@!@!@!@!@!@");
            console.log(
                t(request.requestHeader.timestamp),
                request.requestHeader.requestHandle,
                request.schema.name.padEnd(30, " "),
                " ID =",
                channel.channelId.toString()
            );
            console.log(request.constructor.name, request.toString());
        }
    });

    process.once("SIGINT", function () {
        // only work on linux apparently
        console.error(chalk.red.bold(" Received server interruption from user "));
        console.error(chalk.red.bold(" shutting down ..."));
        server.shutdown(1000, function () {
            console.error(chalk.red.bold(" shutting down completed "));
            console.error(chalk.red.bold(" done "));
            console.error("");
            process.exit(-1);
        });
    });

    server.on("serverRegistered", () => {
        console.log("server has been registered");
    });
    server.on("serverUnregistered", () => {
        console.log("server has been unregistered");
    });
    server.on("serverRegistrationRenewed", () => {
        console.log("server registration has been renewed");
    });
    server.on("serverRegistrationPending", () => {
        console.log("server registration is still pending (is Local Discovery Server up and running ?)");
    });
    server.on("newChannel", (channel) => {
        console.log(
            chalk.bgYellow("Client connected with address = "),
            channel.remoteAddress,
            " port = ",
            channel.remotePort,
            "timeout=",
            channel.timeout
        );
    });
    server.on("closeChannel", (channel) => {        
        console.log(chalk.bgCyan("Client disconnected with address = "), channel.remoteAddress, " port = ", channel.remotePort);
        if (global.gc) {
            global.gc();
        }
    });
    
    // function make_callback(_nodeId) {

    //     let nodeId = _nodeId;
    //     return  function(dataValue) {
    //         console.log("!!!!!!!!!! make_callback !!!!!!!!!!!");
    //         console.log(nodeId.toString() , "\t value : ", dataValue.value.value.toString());
    //    };
    // }
    
    // let subscription = new ClientSubscription(session, {
    //     requestedPublishingInterval: 150,
    //     requestedLifetimeCount: 10 * 60 * 10,
    //     requestedMaxKeepAliveCount: 10,
    //     maxNotificationsPerPublish: 2,
    //     publishingEnabled: true,
    //     priority: 6
    // });
    
    // subscription.on("terminated", function () {
    //     inner_done();
    // });
    
    // let ids = [
    //     "DEV1-ROTOR_RPM",
    //     "DEV1-UV_VOLTAGE",
    //     "DEV1-W_CURRNET",
    // ];
    // ids.forEach(function(id){
    //     let nodeId = "ns=1;s="+id;
    //     let monitoredItem = subscription.monitor(
    //         {nodeId: resolveNodeId(nodeId), attributeId: AttributeIds.Value},
    //         {samplingInterval: 10, discardOldest: true, queueSize: 1});
    //     monitoredItem.on("changed",make_callback(nodeId));
    // });
    
    
    // setTimeout(function() {
    //     subscription.terminate();
    // },5000);

})();
