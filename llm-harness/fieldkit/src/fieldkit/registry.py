"""Explicit module registration keeps startup deterministic and easy to audit."""

from fieldkit.core.module import Module
from fieldkit.modules.api_inventory import APIInventory
from fieldkit.modules.auth_compare import AuthCompare
from fieldkit.modules.auth_matrix import AuthMatrix
from fieldkit.modules.burp_bridge import BurpBridge
from fieldkit.modules.callback_collector import CallbackCollectorModule
from fieldkit.modules.content_discovery import ContentDiscovery
from fieldkit.modules.cors_check import CorsCheck
from fieldkit.modules.evidence_workbench import (
    ActuatorAnalyzer,
    ArtifactTriage,
    AuthFlowMapper,
    EvidenceIngest,
    EvidenceReport,
    HypothesisQueue,
    IDMapper,
    RequestVault,
    RouteMapper,
    SecretCorrelator,
    SerializationWorkbench,
)
from fieldkit.modules.ffuf import Ffuf
from fieldkit.modules.header_review import HeaderReview
from fieldkit.modules.host_resolver import HostResolver
from fieldkit.modules.injection import SQLiCheck, SSRFCheck, XXECheck
from fieldkit.modules.js_review import JSReview
from fieldkit.modules.jwt_check import JWTCheck
from fieldkit.modules.linux import ExposureAudit, LinuxInventory
from fieldkit.modules.mssql_export import MSSQLExport
from fieldkit.modules.network_vantage import NetworkVantage
from fieldkit.modules.nmap_import import NmapImport
from fieldkit.modules.nuclei import Nuclei
from fieldkit.modules.parameter_discovery import ParameterDiscovery
from fieldkit.modules.parameter_map import ParameterMap
from fieldkit.modules.report_export import ReportExport, ReviewUpdate, RunCompare, TeamMerge
from fieldkit.modules.request_replay import RequestReplay
from fieldkit.modules.session_check import SessionCheck
from fieldkit.modules.session_workflow import BrowserLogin, SessionWorkflow
from fieldkit.modules.site_map import SiteMap
from fieldkit.modules.snapshot import Snapshot
from fieldkit.modules.soap_inventory import SOAPInventory
from fieldkit.modules.stored_xss import StoredXSS
from fieldkit.modules.tls_review import TLSReview
from fieldkit.modules.web_artifacts import WebArtifacts
from fieldkit.modules.workflow_verify import WorkflowVerifier


def modules() -> dict[str, Module]:
    builtins: tuple[Module, ...] = (
        WebArtifacts(),
        JSReview(),
        SiteMap(),
        ContentDiscovery(),
        AuthCompare(),
        SessionCheck(),
        HeaderReview(),
        CorsCheck(),
        APIInventory(),
        ParameterMap(),
        TLSReview(),
        Snapshot(),
        ReportExport(),
        RunCompare(),
        TeamMerge(),
        ReviewUpdate(),
        LinuxInventory(),
        ExposureAudit(),
        NmapImport(),
        Nuclei(),
        RequestReplay(),
        SSRFCheck(),
        XXECheck(),
        SQLiCheck(),
        SOAPInventory(),
        AuthMatrix(),
        SessionWorkflow(),
        BrowserLogin(),
        EvidenceIngest(),
        RequestVault(),
        RouteMapper(),
        IDMapper(),
        HostResolver(),
        ActuatorAnalyzer(),
        ArtifactTriage(),
        WorkflowVerifier(),
        AuthFlowMapper(),
        SecretCorrelator(),
        SerializationWorkbench(),
        HypothesisQueue(),
        EvidenceReport(),
        BurpBridge(),
        ParameterDiscovery(),
        JWTCheck(),
        Ffuf(),
        StoredXSS(),
        CallbackCollectorModule(),
        NetworkVantage(),
        MSSQLExport(),
    )
    return {module.name: module for module in builtins}
