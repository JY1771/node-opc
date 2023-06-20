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
const fetch = require("node-fetch");
const mysql = require('mysql'); // mysql 변수에 mysql 모듈을 할당
// const connection = mysql.createConnection({  //커넥션변수에 mysql변수에 있는 크리에이드커넥션 메소드를 호출(객체를 받음) 할당
//     host    : '127.0.0.1',   //host객체 - 마리아DB가 존재하는 서버의 주소
//     user    : 'root', //user객체 - 마리아DB의 계정
//     password    : 'lsis6535',   //password객체 - 마리아DB 계정의 비밀번호
//     database    : 'wind_power'   //database객체 - 접속 후 사용할 DB명
// });
// connection.connect();   // (위에 선언한 객체들을 가진)커넥션변수의 connect() 메소드를 호출하면 DB에 접속이 됨

const pool = mysql.createPool({
    connectionLimit: 100, // 최대 연결 수
    host    : '127.0.0.1',   //host객체 - 마리아DB가 존재하는 서버의 주소
    user    : 'root', //user객체 - 마리아DB의 계정
    password    : 'lsis6535',   //password객체 - 마리아DB 계정의 비밀번호
    database    : 'wind_power'   //database객체 - 접속 후 사용할 DB명
  });


let mapInfos = [];
let columnNames = [];
let columnIds = [];

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
const { result, values } = require("underscore");
const { send } = require("process");

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

    async function make_table() {        
        let now = new Date();  // 현재 날짜와 시간을 가져옴
        let year = now.getFullYear().toString();  // 현재 연도를 문자열로 변환
        let month = (now.getMonth() + 1).toString().padStart(2, "0");  // 현재 월을 문자열로 변환하고 2자리로 만듦
        let yyyyMM = year + month;  // yyyyMM 형식으로 포맷팅된 문자열
        
        const tableName = 'tb_unifi_data_'+yyyyMM;        
        

        const createTableQuery = `CREATE TABLE IF NOT EXISTS ${tableName} (
            no int(11) NOT NULL AUTO_INCREMENT,
            \`updated\` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
            \`TURBIN-ID\` int(11) DEFAULT NULL COMMENT '터빈아이디',
            \`WTUR-AvlTmRs\` double DEFAULT NULL COMMENT '발전기 가동시간(vendor-specific) ',
            \`WTUR-OpTmRs\` double DEFAULT NULL COMMENT '발전기 운전시간(vendor-specific) ',
            \`WTUR-StrCnt\` int(11) DEFAULT NULL COMMENT '발전기 운전수량(vendor-specific)',
            \`WTUR-StopCnt\` int(11) DEFAULT NULL COMMENT '발전기 정지수량(vendor-specific)',
            \`WTUR-TotWh\` int(11) DEFAULT NULL COMMENT '누적 유효전력량(net)',
            \`WTUR-TotVArh\` double DEFAULT NULL COMMENT '누적 무효전력량(net)',
            \`WTUR-DmdWh\` double DEFAULT NULL COMMENT '유효전력량(demand)',
            \`WTUR-DmdVArH\` double DEFAULT NULL COMMENT '무효전력량(demand)',
            \`WTUR-SupWh\` double DEFAULT NULL COMMENT '유효전력량(supply)',
            \`WTUR-SupVArh\` double DEFAULT NULL COMMENT '무효전력량(supply)',
            \`WTUR-TurSt\` int(11) DEFAULT NULL COMMENT '발전기 상태',
            \`WTUR-W\` double DEFAULT NULL COMMENT '유효전력 출력',
            \`WTUR-Var\` double(22,0) DEFAULT NULL COMMENT '무효전력 출력',
            \`WTUR-SetTurOp\` int(11) DEFAULT NULL COMMENT '발전기 동작 명령',
            \`WTUR-VArOvW\` int(11) DEFAULT NULL COMMENT '유효전력 명령보다 무효전력 우선',
            \`WTUR-VARefPri\` int(11) DEFAULT NULL COMMENT '발전기 무효전력 설정치 우선 명령',
            \`WTUR-DmdW\` double(22,0) DEFAULT NULL COMMENT '발전기 유효전력 출력 설정치',
            \`WTUR-DmdVAr\` double(22,0) DEFAULT NULL COMMENT '발전기 무효전력 출력 설정치',
            \`WTUR-DmdPF\` float DEFAULT NULL COMMENT '발전기 역률 설정치',
            \`WROT-RotSt\` int(11) DEFAULT NULL COMMENT 'rotor 상태',
            \`WROT-BlStBl1\` int(11) DEFAULT NULL COMMENT 'blade 1 상태(Ref.)',
            \`WROT-BlStBl2\` int(11) DEFAULT NULL COMMENT 'blade 2 상태',
            \`WROT-BlStBl3\` int(11) DEFAULT NULL COMMENT 'blade 3 상태',
            \`WROT-PtCtlSt\` int(11) DEFAULT NULL COMMENT 'pitch 제어 상태',
            \`WROT-RotSpd\` float DEFAULT NULL COMMENT 'rotor 속도(로터측)',
            \`WROT-RotSpos\` float DEFAULT NULL COMMENT 'rotor 위치 각도',
            \`WROT-HubTmp\` float DEFAULT NULL COMMENT 'rotor 허브내부 온도',
            \`WROT-PtHyPreBl1\` float DEFAULT NULL COMMENT 'blade1 유압 피치시스템 압력(Ref.)',
            \`WROT-PtHyPreBl2\` float DEFAULT NULL COMMENT 'blade2 유압 피치시스템 압력',
            \`WROT-PtHyPreBl3\` float DEFAULT NULL COMMENT 'blade3 유압 피치시스템 압력',
            \`WROT-PtAngSpBbl1\` float DEFAULT NULL COMMENT 'blade 1 피치 각도 설정치(Ref.)',
            \`WROT-PtAngSpBbl2\` float DEFAULT NULL COMMENT 'blade 2 피치 각도 설정치',
            \`WROT-PtAngSpBbl3\` float DEFAULT NULL COMMENT 'blade 3 피치 각도 설정',
            \`WROT-PtAngValBl1\` float DEFAULT NULL COMMENT 'blade 1 피치각도(Ref.)',
            \`WROT-PtAngValBl2\` float DEFAULT NULL COMMENT 'blade 2 피치각도',
            \`WROT-PtAngValBl3\` float DEFAULT NULL COMMENT 'blade 3 피치각도',
            \`WROT-BlkRot\` int(11) DEFAULT NULL COMMENT 'Blocked 위치로 로터 설정',
            \`WROT-PtEmgchk\` int(11) DEFAULT NULL COMMENT 'Emergency 피치시스템 check',
            \`WTRM-BrkOpMod\` int(11) DEFAULT NULL COMMENT 'shaft 브레이크 상태',
            \`WTRM-LuSt\` int(11) DEFAULT NULL COMMENT '기어박스 윤활 시스템 상태',
            \`WTRM-FtrSt\` int(11) DEFAULT NULL COMMENT '여과장치 시스템 상태',
            \`WTRM-ClSt\` int(11) DEFAULT NULL COMMENT 'Cooling 시스템 상태',
            \`WTRM-HtSt\` int(11) DEFAULT NULL COMMENT 'Heating 시스템 상태',
            \`WTRM-OilLevSt\` int(11) DEFAULT NULL COMMENT '기어박스 오일레벨 상태',
            \`WTRM-OfFltSt\` int(11) DEFAULT NULL COMMENT 'Offline 필터 상태',
            \`WTRM-InlFltSt\` int(11) DEFAULT NULL COMMENT 'Inline 필터 상태',
            \`WTRM-TrTmpShfBrg1\` float DEFAULT NULL COMMENT '온도(shaft 베어링 1)',
            \`WTRM-TrTmpShfBrg2\` float DEFAULT NULL COMMENT '온도(shaft 베어링 2)',
            \`WTRM-TrmTmpGbxOil\` float DEFAULT NULL COMMENT '기어박스 오일 온도',
            \`WTRM-TrmTmpShfBrk\` float DEFAULT NULL COMMENT 'Shaft 브레이크 표면온도',
            \`WTRM-VibGbx1\` float DEFAULT NULL COMMENT '기어박스(1) 진동',
            \`WTRM-VibGbx2\` float DEFAULT NULL COMMENT '기어박스(2) 진동',
            \`WTRM-GsLev\` float DEFAULT NULL COMMENT '윤할장치 grease 레벨(메인 shaft)',
            \`WTRM-GbxOilLev\` float DEFAULT NULL COMMENT '기어박스 오일레벨',
            \`WTRM-GbxOilPres\` float DEFAULT NULL COMMENT '기어오일 압력',
            \`WTRM-BrkHyPres\` float DEFAULT NULL COMMENT '유압압력(shaft 브레이크)',
            \`WTRM-OfFlt\` float DEFAULT NULL COMMENT 'Offline 필터 오염도',
            \`WTRM-Inflt\` float DEFAULT NULL COMMENT 'Inline 필터 오염도',
            \`WCNV-OptmRs\` double(22,0) DEFAULT NULL COMMENT 'Converter 동작시간',
            \`WCNV-CnvOpMod\` int(11) DEFAULT NULL COMMENT 'Converter 동작모드',
            \`WCNV-ClSt\` int(11) DEFAULT NULL COMMENT 'Cooling 시스템 상태',
            \`WCNV-Hz\` float DEFAULT NULL COMMENT '주파수',
            \`WCNV-Torq\` float DEFAULT NULL COMMENT '토크',
            \`WCNV-GnPPV\` float DEFAULT NULL COMMENT '3상 상간전압(Generator 측)',
            \`WCNV-GnPhV\` float DEFAULT NULL COMMENT '3상 상전압(Generator 측)',
            \`WCNV-GnA\` float DEFAULT NULL COMMENT '3상 전류(Generator측)',
            \`WCNV-GnPF\` float DEFAULT NULL COMMENT '3상 PF(Generator측)',
            \`WCNV-GriPPv\` float DEFAULT NULL COMMENT '3상 상간전압(Grid 측)',
            \`WCNV-GriPhv\` float DEFAULT NULL COMMENT '3상 상전압(Grid측)',
            \`WCNV-GriA\` float DEFAULT NULL COMMENT '3상 전류(Grid측)',
            \`WCNV-GriPF\` float DEFAULT NULL COMMENT '3상 역률(Grid측)',
            \`WCNV-CnvTmpGn\` float DEFAULT NULL COMMENT '온도(컨버터-Gen.측)',
            \`WCNV-CnvTmpDcling\` float DEFAULT NULL COMMENT '온도(컨버터 내부)',
            \`WCNV-CnvTmpGri\` float DEFAULT NULL COMMENT '온도(컨버터-Grid측)',
            \`WCNV-Dclvol\` float DEFAULT NULL COMMENT 'DC-link 전압(컨버터 내부)',
            \`WCNV-DclAmp\` float DEFAULT NULL COMMENT 'DC-link 전류(컨버터 내부)',
            \`WTRF-TrfOpTmRs\` double(22,0) DEFAULT NULL COMMENT '변압기 동작시간(vendor Specific)',
            \`WTRF-TrfClSt\` int(11) DEFAULT NULL COMMENT 'Cooling 시스템 상태(변압기)',
            \`WTRF-OilLevSt\` int(11) DEFAULT NULL COMMENT '오일레벨 정보(오일 변압기)',
            \`WTRF-MTPreSt\` int(11) DEFAULT NULL COMMENT '메인탱크 Gas 압력(오일 변압기)',
            \`WTRF-TrfTurPPV\` float DEFAULT NULL COMMENT '3상 상간전압(터빈측)',
            \`WTRF-TrfTurPhV\` float DEFAULT NULL COMMENT '3상 상전압(터빈측)',
            \`WTRF-TrfTurA\` float DEFAULT NULL COMMENT '3상 전류( 터빈측)',
            \`WTRF-TrfGriPPV\` float DEFAULT NULL COMMENT '3상 상간전압(Grid측)',
            \`WTRF-TrfGriPhV\` float DEFAULT NULL COMMENT '3상 상전압(Grid측)',
            \`WTRF-TrfGriA\` float DEFAULT NULL COMMENT '3상 전류(Grid측)',
            \`WTRF-TrfTmpTrfTur\` float DEFAULT NULL COMMENT '온도(터빈측)',
            \`WTRF-TrfTmpTrfGri\` float DEFAULT NULL COMMENT '온도(Grid측)',
            \`WTRF-AtvGriSw\` int(11) DEFAULT NULL COMMENT '메인 Grid S/W 동작 명령',
            \`WNAC-BecTmRs\` double(22,0) DEFAULT NULL COMMENT 'Beacon 동작 시간',
            \`WNAC-BecBulbSt\` int(11) DEFAULT NULL COMMENT 'Beacon 상태',
            \`WNAC-WdHtSt\` int(11) DEFAULT NULL COMMENT '풍속감지기 히터 상태',
            \`WNAC-IceSt\` int(11) DEFAULT NULL COMMENT '결빙탐지기 상태',
            \`WNAC-AneSt\` int(11) DEFAULT NULL COMMENT '풍속계 상태',
            \`WNAC-Dir\` float DEFAULT NULL COMMENT '나셀 방향',
            \`WNAC-WdSpd\` float DEFAULT NULL COMMENT '나셀 외부 풍속',
            \`WNAC-WdDir\` float DEFAULT NULL COMMENT '나셀 외부 풍향',
            \`WNAC-ExTmp\` float DEFAULT NULL COMMENT '나셀 외부 온도',
            \`WNAC-lntlTmp\` float DEFAULT NULL COMMENT '나셀 내부 습도',
            \`WNAC-BecLumLev\` float DEFAULT NULL COMMENT 'Beacon 광도 레벨',
            \`WNAC-Vis\` float DEFAULT NULL COMMENT '나셀 외부 시정도',
            \`WNAC-Ice\` float DEFAULT NULL COMMENT '결빙 두께',
            \`WNAC-DispXdir\` float DEFAULT NULL COMMENT '타워 변위(경도방향)',
            \`WNAC-DispYdir\` float DEFAULT NULL COMMENT '타워 변위(위도방향)',
            \`WNAC-SetBecMod\` int(11) DEFAULT NULL COMMENT 'Beacon modus 설정',
            \`WNAC-SetBecLev\` int(11) DEFAULT NULL COMMENT 'Beacon 전구 레벨 설정',
            \`WNAC-SetFlsh\` int(11) DEFAULT NULL COMMENT 'Beacon 플래시 듀티 사이클 설정',
            \`WYAW-CwTm\` double(22,0) DEFAULT NULL COMMENT 'Yaw 동작시간(CW )',
            \`WYAW-CcwTm\` double(22,0) DEFAULT NULL COMMENT 'Yaw 동작시간(CCW)',
            \`WYAW-YwSt\` int(11) DEFAULT NULL COMMENT 'Yaw 시스템 모드',
            \`WYAW-YwBrakeSt\` int(11) DEFAULT NULL COMMENT 'Yaw 브레이크 모드',
            \`WYAW-YwSpd\` float DEFAULT NULL COMMENT 'Yaw 속도',
            \`WYAW-Tmp\` float DEFAULT NULL COMMENT 'Yaw 모터기어 온도',
            \`WYAW-YaWAng\` float DEFAULT NULL COMMENT 'Yaw 베어링 회전각(true north대비)',
            \`WYAW-CabWup\` double(22,0) DEFAULT NULL COMMENT 'cable windup',
            \`WYAW-SysGsLev\` double(22,0) DEFAULT NULL COMMENT 'Yaw 시스템 윤활장치 그리스 레벨',
            \`WYAW-BrkPres\` float DEFAULT NULL COMMENT 'Yaw 브레이크 압력',
            \`WYAW-AtvYw\` int(11) DEFAULT NULL COMMENT 'Yaw 명령',
            \`WTOW-LiftSt\` int(11) DEFAULT NULL COMMENT 'Lift 시스템 상태',
            \`WTOW-DeHumSt\` int(11) DEFAULT NULL COMMENT '제습기 상태',
            \`WTOW-HtexSt\` int(11) DEFAULT NULL COMMENT '열교환기 상태',
            \`WTOW-LiftPos\` double(22,0) DEFAULT NULL COMMENT 'Lift 위치',
            \`WMET-IntlHum\` float DEFAULT NULL COMMENT '타워 내부 습도',
            \`WMET-MetAlt1Alt\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-고도 센서',
            \`WMET-MetAlt1horWdSpd\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-수평 풍속',
            \`WMET-MetAlt1VerWdSpd\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-수직 풍속',
            \`WMET-MetAlt1HorWdDir\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-수평 풍향',
            \`WMET-MetAlt1VerWdDir\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-수직 풍향',
            \`WMET-MetAlt1Tmp\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-온도',
            \`WMET-MetAlt1Hum\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-습도',
            \`WMET-MetAlt1Pres\` float DEFAULT NULL COMMENT 'Meteorogical altitude1-압력',
            \`WGEN-OptmRs\` double(22,0) DEFAULT NULL COMMENT 'Generator 동작시간',
            \`WGEN-GnOpMod\` int(11) DEFAULT NULL COMMENT 'Generator 동작 모드',
            \`WGEN-ClSt\` int(11) DEFAULT NULL COMMENT 'Generator cooling 시스템 상태',
            \`WGEN-Spd\` float DEFAULT NULL COMMENT 'Generator 속도',
            \`WGEN-W\` double(22,0) DEFAULT NULL COMMENT 'Generator 유효전력',
            \`WGEN-VAr\` double(22,0) DEFAULT NULL COMMENT 'Generator 무효전력',
            \`WGEN-GnTmpSta\` float DEFAULT NULL COMMENT 'Generator Stator 온도',
            \`WGEN-GnTmpRtr\` float DEFAULT NULL COMMENT 'Generator Rotor 온도',
            \`WGEN-GnTmoInlet\` float DEFAULT NULL COMMENT 'Generator Stator 입력단 온도',
            \`WGEN-StaPPV\` float DEFAULT NULL COMMENT 'Generator Stator 3상 상간전압',
            \`WGEN-StaPhV\` float DEFAULT NULL COMMENT 'Generator Stator 3상 전압',
            \`WGEN-StaA\` float DEFAULT NULL COMMENT 'Generator Stator 3상 전류 ',
            \`WGEN-RtrPPv\` float DEFAULT NULL COMMENT 'Gnerator Rotor 3상 상간 전압',
            \`WGEN-RtrPhV\` float DEFAULT NULL COMMENT 'Genrator Rotor 3상 전압',
            \`WGEN-RtrA\` float DEFAULT NULL COMMENT 'Generator Rotor 3상 전류',
            \`WGEN-RtrExtDC\` float DEFAULT NULL COMMENT 'Generator Rotor DC 여자 전압',
            \`WGEN-RtrExtAC\` float DEFAULT NULL COMMENT 'Generator Rotor AC 여자 전압',
            \`WAPC-AlmSt\` int(11) DEFAULT NULL COMMENT '경보 설정 상태',
            \`WAPC-EvtTm\` double(22,0) DEFAULT NULL COMMENT 'oldest 동적 알람 timestamp',
            \`WAPC-NumOpTur\` int(11) DEFAULT NULL COMMENT '가동중인 발전기 수량',
            \`PIWLimEn\` int(11) DEFAULT NULL COMMENT '유효전력 제한 모드 enabled',
            \`WAPC-PIVAEn\` int(11) DEFAULT NULL COMMENT '유효전력 제어모드 enabled(피상전력제어)',
            \`WAPC-PIGRAEn\` int(11) DEFAULT NULL COMMENT 'Gradient 기능 enabled',
            \`WAPC-PIDelEn\` int(11) DEFAULT NULL COMMENT 'Delta 기능 enabled',
            \`WAPC-PIWCap\` int(11) DEFAULT NULL COMMENT '풍력단지 유효전력 출력 능력',
            \`WAPC-PIW\` double(22,0) DEFAULT NULL COMMENT '풍력단지 유효전력 출력',
            \`WAPC-PIVA\` double(22,0) DEFAULT NULL COMMENT '풍력단지 피상전력',
            \`WAPC-PIGra\` double(22,0) DEFAULT NULL COMMENT '풍력단지 Gradient',
            \`WAPC-PiWDel\` double(22,0) DEFAULT NULL COMMENT 'Delta 기능을 이용한 유효전력 예비',
            \`WAPC-PIWAtv\` int(11) DEFAULT NULL COMMENT '유효전력 제어기능 동작',
            \`WAPC-PIVAAtv\` int(11) DEFAULT NULL COMMENT '피상전력 제어기능 동작',
            \`WAPC-PIGraAtv\` int(11) DEFAULT NULL COMMENT 'Gradient 제어기능 동작',
            \`WAPC-SetPIW\` int(11) DEFAULT NULL COMMENT '단지 유효전력 출력 기준치설정',
            \`WAPC-SetPIVA\` int(11) DEFAULT NULL COMMENT '단지 피상전력 출력 기준치설정',
            \`WAPC-SetPIWUpGra\` int(11) DEFAULT NULL COMMENT '단지 유효전력 gradient Up기준치 설정',
            \`WAPC-SetPIWDoGra\` int(11) DEFAULT NULL COMMENT '단지 유효전력 gradient Down 설정',
            \`WAPC-SetPIDel\` int(11) DEFAULT NULL COMMENT '단지 예비 유효전력 기준치 설정',
            \`WRPC-NumOpTur\` int(11) DEFAULT NULL COMMENT '운전중인 발전기 대수',
            \`WRPC-PIVArMode\` int(11) DEFAULT NULL COMMENT '무효전력 제어 모드',
            \`WRPC-PIVAr\` double(22,0) DEFAULT NULL COMMENT '풍력단지 무효전력 출력',
            \`WRPC-PIVArCaplmo\` double(22,0) DEFAULT NULL COMMENT '풍력단지 무효전력 수요량',
            \`WRPC-PIVArCapExp\` double(22,0) DEFAULT NULL COMMENT '풍력단지 무효전력 공급량',
            \`WRPC-PIPF\` float DEFAULT NULL COMMENT '풍력단지 역률',
            \`WRPC-PIV\` float DEFAULT NULL COMMENT '풍력단지 출력 전압(외부 grid 연결점)',
            \`WRPC-PIVArAtv\` int(11) DEFAULT NULL COMMENT '무효전력 제어기능 동작',
            \`WRPC-SetPIVAr\` int(11) DEFAULT NULL COMMENT '단지 무효전력 출력 기준치 설정',
            \`WRPC-SetPIVArUpGra\` int(11) DEFAULT NULL COMMENT '단지 무효전력 gradient up 기준치 설정',
            \`WRPC-SetPIVDoGra\` int(11) DEFAULT NULL COMMENT '단지 무효전력 gradient down 기준치 설정',
            \`WRPC-SetPIV\` int(11) DEFAULT NULL COMMENT '단지 전압 출력 기준치 설정',
            \`WRPC-SetPIVUpGra\` int(11) DEFAULT NULL COMMENT '단지 전압 ramping up 기준치 설정',
            \`WRPC-SetPIVDoGra2\` int(11) DEFAULT NULL COMMENT '단지 전압 ramping down 기준치 설정',
            \`WRPC-SetPIDrp\` int(11) DEFAULT NULL COMMENT '전압 제어 droop 기울기 기준치 설정',
            \`WRPC-SetPIPF\` int(11) DEFAULT NULL COMMENT '단지 역률 기준치 설정',
            PRIMARY KEY (no)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8`;
          
        pool.getConnection((err, connection) => {
            if (err) {
              // 에러 처리
              console.error('Error getting connection from pool:', err);
              return;
            }
          
            connection.query(createTableQuery, (error, results, fields) => {
              connection.release(); // Connection 반환
              if (error) {
                // 에러 처리
                console.error('Error executing query:', error);
                return;
              }
            });
          });
    }
    
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

            pool.getConnection((err, connection) => {
                if (err) {
                  // 에러 처리
                  console.error('Error getting connection from pool:', err);
                  return;
                }
              
                connection.query('SELECT * FROM tb_turbine', (error, results, fields) => {
                  connection.release(); // Connection 반환
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
              });
        }

        await makeTurbineOriginTables();

        //let mappingInfo = {};
        

        const getMappingInfo = async () =>{
            mapInfos = [];

            pool.getConnection((err, connection) => {
                if (err) {
                  // 에러 처리
                  console.error('Error getting connection from pool:', err);
                  return;
                }
              
                connection.query('SELECT model FROM tb_mapping', (error, results, fields) => {
                  connection.release(); // Connection 반환
                 
                if (error) {
                    console.log(error);
                    return null;
                } //에러에 값이 있다면 에러값을 콘솔에 출력

                
                if(results.length > 0){
                    for(let i=0; i<results.length; i++){                              
                        
                        pool.getConnection((err, conn) => {  

                            conn.query('SELECT mapping FROM tb_mapping where model = "'+results[i].model+'"', function(error2, results2, fields){          
                                
                                conn.release(); // Connection 반환

                                if (error2) {
                                    console.log(error2);
                                    return null;
                                } //에러에 값이 있다면 에러값을 콘솔에 출력
                                
                                if(results2.length > 0){
                                    let info = results2[0].mapping;                                   
                                    mapInfos.push(JSON.parse(info));                                
                                }
                            });
                          });
                    }
                  }
                
                });
              });
            
        }
        
        await getMappingInfo();


        /*
         * letiation 0:
         * ------------
         *
         * Add a letiable in folder using a raw letiant.
         * Use this letiation when the letiable has to be read or written by the OPCUA clients
         */
        
        const makeUnifiledNodeList = async () => {
            columnNames = [];

            pool.getConnection((err, connection) => {
                if (err) {
                  // 에러 처리
                  console.error('Error getting connection from pool:', err);
                  return;
                }
              
                connection.query('SELECT * FROM tb_unified_definition', function(error, results, fields){                
                    connection.release();
                    if (error) {
                        console.log(error);
                        return null;
                    } 
                    let cnt = 1;
                    if(results.length > 0){                       
                        
                        for(let i=0; i<results.length; i++){                    
                            
                            try {
                                let n = String(results[i].ln) + '-' +String(results[i].name);
    
                                columnNames.push(n);
                                columnIds.push(results[i].id);
    
                                let dt = results[i].attribute_name;
                                let _dataType = "Double";
                                let dataType = DataType.Double;
                                let defaultValue = 0;
                                
                                if(dt == "Boolean") {
                                    _dataType = "Boolean";
                                    dataType = DataType.Boolean;
                                    defaultValue = false;
                                }
                                
                                console.log("Data Map info check no. ",cnt+" : ",n);
    
                                cnt = cnt + 1
    
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
                                            // console.log("Client SET Value nodeName : ",n+" / Value : "+variant.value);                                        
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
              });
              
        }

        await makeUnifiledNodeList();

        
        let values = [];
        let ids = 0;

        const makeTurbinOriginNodeList = async (turbineOriginTables) => {            

            for(let j=0; j<turbineOriginTables.length; j++){

                pool.getConnection((err, connection) => {
                    if (err) {
                      // 에러 처리
                      console.error('Error getting connection from pool:', err);
                      return;
                    }
                  
                    connection.query("SHOW COLUMNS FROM wind_power."+turbineOriginTables[j].data_table , async (error, results) => {
                        connection.release();
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
                                                // console.log("Client SET Value nodeName : ",n+" / Value : "+variant.value);                                        
                                                
                                                values.push(variant.value);
                                                ids = ids+1;
    
                                                console.log("Turbin id : "+turbineOriginTables[j].dev_id+" / Data Convert no."+ids+" complete. value : "+n);
    
                                                if(results.length == ids) {
                                                    insertData(turbineOriginTables[j].dev_id);                                                
                                                }
    
    
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
                  });

            }
            
        }

        let insertData = (turbinId) =>{
            const date = new Date();                   
            console.log('---------------- Received & Convert locale time (ko-kr): ' + date.toLocaleString('ko-kr')+"----------------");

            ids = 0;
            let insertObj = {};
            let sendObj = {};

            if(mapInfos.length > 0 ){
                
                loop2 : for(let a=0; a<mapInfos.length; a++){

                    let mappingInfo = mapInfos[a];

                    for (const [key, value] of Object.entries(mappingInfo)) {            
                        insertObj[key] = null;     
                    }            
            
                    
                    for(let i=0; i<columnNames.length; i++){        
                        loop : for (const [key, value] of Object.entries(mappingInfo)) {         
                            
                            if(key == columnNames[i]){    
                                           
                                if(values[i] !== undefined){                                    
                                    insertObj[key] = values[i];                                                
                                    sendObj[columnIds[i]] = values[i];
                                } 
            
                                break loop;
                            } 
                        }
                
                    }
        
                    // sendApi(sendObj, turbinId);//카프카
    
                    let now = new Date();  // 현재 날짜와 시간을 가져옴
                    let year = now.getFullYear().toString();  // 현재 연도를 문자열로 변환
                    let month = (now.getMonth() + 1).toString().padStart(2, "0");  // 현재 월을 문자열로 변환하고 2자리로 만듦
                    let yyyyMM = year + month;  // yyyyMM 형식으로 포맷팅된 문자열                    
                    
                     let sql = "INSERT INTO tb_unifi_data_"+yyyyMM+" (";
            
                     sql = sql +"`TURBIN-ID`,";

                       for (const [key, value] of Object.entries(insertObj)) {
                            sql = sql +"`"+key+ "`,";
                        }
                        
                        sql = sql.slice(0, -1);
                        sql = sql + ") VALUES (";
                                              
                        sql = sql +turbinId+ ",";
                        for (const [key, value] of Object.entries(insertObj)) {
                            sql = sql +value+ ",";
                        }
            
                        sql = sql.slice(0, -1);
                        sql = sql+")"
                   
            
                    // console.log(sql);

                    pool.getConnection((err, connection) => {
                        if (err) {
                          // 에러 처리
                          console.error('Error getting connection from pool:', err);
                          return;
                        }
                      
                        connection.query(sql , async (error, results) => {
                            connection.release();
                            if (error) {
                                console.log(error);
                                return null;
                            } //에러에 값이 있다면 에러값을 콘솔에 출력
                
                            await console.log("데이터 인서트");            
                            values = [];           
                           
                        });

                      }); 
                      
                      break loop2;

                      
                }
            }
    
        }

        let timestamp = () => {
            var today = new Date();
            today.setHours(today.getHours() + 9);
            return today.toISOString().replace('T', ' ').substring(0, 19);
        }


        const sendApi = (data, turbinId) => {
           
            let status;
            let response;
            let time = timestamp();
            data.time = time;
            data['TURBIN-ID'] = turbinId;
            
            console.log(data);
            // console.log(data);

            fetch(`http://27.96.134.95:8082/topics/test-kafka`, {
                headers : {
                    "Content-Type": "application/vnd.kafka.json.v2+json",
                    "Accept": "application/vnd.kafka.v2+json"
                },
                method: "POST",
                body: JSON.stringify({
                    "records": [
                        {
                            "value" : data
                        }
                    ]
                }),
            })
            .then((res) => { 
                status = res.status; 
                response = res;
                return res.json() 
              })
              .then((jsonResponse) => {                
                console.log("::::::CALL API ::: status : ",status," : time : ",time, " : response : ",response);
              })
              .catch((err) => {
                console.error(err);
              });
        }

    }

    post_initialize();
    make_table();

    // const callApi =async () => {
    //     fetch(`http://119.66.125.106:9501/jchiDTH/getTime`, {
    //         headers : { 
    //           'Content-Type': 'application/json',
    //           'Accept': 'application/json'
    //          }
      
    //       })
    //       .then((response) => response.text())
    //       .then((text) => {
    //         console.log(":::::: CALL API TIME IS : "+text);
    //       });
    // }
    

    // setInterval(() => {
    //     callApi();    
    // }, 60000);

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
            // console.log("%*%*%*%*%*%*%* response %*%*%*%*%*%*%*");
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
            // console.log("!@!@!@!@!@!@!@ request !@!@!@!@!@!@!@");
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
