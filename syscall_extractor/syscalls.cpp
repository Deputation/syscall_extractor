#include "common.hpp"

std::string syscall_t::get_name()
{
	return this->name;
}

void* syscall_t::get_address()
{
	return this->address;
}

uint32_t syscall_t::get_id()
{
	if (this->id_initialized)
	{
		return this->id;
	}

	if (!this->address)
	{
		this->id_initialized = true;
		this->id = e_syscall_extractor_errors::syscall_address_not_found;

		return this->id;
	}

	auto disassembly_output = disassembler::zydis->disassemble(this->address, 8);
	auto mov_eax_string = std::string();

	auto found_eax = false;

	for (const auto& instruction : disassembly_output)
	{
		if (instruction.find("mov eax") != std::string::npos)
		{
			mov_eax_string = instruction;

			found_eax = true;
			break;
		}
	}

	if (!found_eax)
	{	
		this->id = e_syscall_extractor_errors::mov_eax_instruction_not_found;
		this->id_initialized = true;

		return this->id;
	}
	
	auto comma_position = mov_eax_string.find(',');
	auto number_as_string = mov_eax_string.substr(comma_position + 2);
	
	uint32_t final_syscall_id;

	std::stringstream stream;
	stream << std::hex << number_as_string;

	stream >> final_syscall_id;
	this->id = final_syscall_id;
	this->id_initialized = true;

	return this->id;
}

syscall_t::syscall_t(std::string name) : 
	name(name), id(e_syscall_extractor_errors::uninitialized), 
	address(GetProcAddress(LoadLibrary(L"ntdll.dll"), name.c_str())), id_initialized(false)
{
	
}

std::vector<std::shared_ptr<syscall_t>> data::syscall_data;

uint32_t data::get_syscall_id(std::string name)
{
	for (const auto& syscall : syscall_data)
	{
		if (!syscall->get_name().compare(name))
		{
			return syscall->get_id();
		}
	}

	return e_syscall_extractor_errors::syscall_name_not_found;
}

const char* const data::windows_20h2_syscalls[] = { "NtAccessCheck", "NtWorkerFactoryWorkerReady", "NtAcceptConnectPort", "NtMapUserPhysicalPagesScatter", "NtWaitForSingleObject", "NtCallbackReturn", "NtReadFile", "NtDeviceIoControlFile", "NtWriteFile", "NtRemoveIoCompletion", "NtReleaseSemaphore", "NtReplyWaitReceivePort", "NtReplyPort", "NtSetInformationThread", "NtSetEvent", "NtClose", "NtQueryObject", "NtQueryInformationFile", "NtOpenKey", "NtEnumerateValueKey", "NtFindAtom", "NtQueryDefaultLocale", "NtQueryKey", "NtQueryValueKey", "NtAllocateVirtualMemory", "NtQueryInformationProcess", "NtWaitForMultipleObjects32", "NtWriteFileGather", "NtSetInformationProcess", "NtCreateKey", "NtFreeVirtualMemory", "NtImpersonateClientOfPort", "NtReleaseMutant", "NtQueryInformationToken", "NtRequestWaitReplyPort", "NtQueryVirtualMemory", "NtOpenThreadToken", "NtQueryInformationThread", "NtOpenProcess", "NtSetInformationFile", "NtMapViewOfSection", "NtAccessCheckAndAuditAlarm", "NtUnmapViewOfSection", "NtReplyWaitReceivePortEx", "NtTerminateProcess", "NtSetEventBoostPriority", "NtReadFileScatter", "NtOpenThreadTokenEx", "NtOpenProcessTokenEx", "NtQueryPerformanceCounter", "NtEnumerateKey", "NtOpenFile", "NtDelayExecution", "NtQueryDirectoryFile", "NtQuerySystemInformation", "NtOpenSection", "NtQueryTimer", "NtFsControlFile", "NtWriteVirtualMemory", "NtCloseObjectAuditAlarm", "NtDuplicateObject", "NtQueryAttributesFile", "NtClearEvent", "NtReadVirtualMemory", "NtOpenEvent", "NtAdjustPrivilegesToken", "NtDuplicateToken", "NtContinue", "NtQueryDefaultUILanguage", "NtQueueApcThread", "NtYieldExecution", "NtAddAtom", "NtCreateEvent", "NtQueryVolumeInformationFile", "NtCreateSection", "NtFlushBuffersFile", "NtApphelpCacheControl", "NtCreateProcessEx", "NtCreateThread", "NtIsProcessInJob", "NtProtectVirtualMemory", "NtQuerySection", "NtResumeThread", "NtTerminateThread", "NtReadRequestData", "NtCreateFile", "NtQueryEvent", "NtWriteRequestData", "NtOpenDirectoryObject", "NtAccessCheckByTypeAndAuditAlarm", "NtQuerySystemTime", "NtWaitForMultipleObjects", "NtSetInformationObject", "NtCancelIoFile", "NtTraceEvent", "NtPowerInformation", "NtSetValueKey", "NtCancelTimer", "NtSetTimer", "NtAccessCheckByType", "NtAccessCheckByTypeResultList", "NtAccessCheckByTypeResultListAndAuditAlarm", "NtAccessCheckByTypeResultListAndAuditAlarmByHandle", "NtAcquireCrossVmMutant", "NtAcquireProcessActivityReference", "NtAddAtomEx", "NtAddBootEntry", "NtAddDriverEntry", "NtAdjustGroupsToken", "NtAdjustTokenClaimsAndDeviceGroups", "NtAlertResumeThread", "NtAlertThread", "NtAlertThreadByThreadId", "NtAllocateLocallyUniqueId", "NtAllocateReserveObject", "NtAllocateUserPhysicalPages", "NtAllocateUserPhysicalPagesEx", "NtAllocateUuids", "NtAllocateVirtualMemoryEx", "NtAlpcAcceptConnectPort", "NtAlpcCancelMessage", "NtAlpcConnectPort", "NtAlpcConnectPortEx", "NtAlpcCreatePort", "NtAlpcCreatePortSection", "NtAlpcCreateResourceReserve", "NtAlpcCreateSectionView", "NtAlpcCreateSecurityContext", "NtAlpcDeletePortSection", "NtAlpcDeleteResourceReserve", "NtAlpcDeleteSectionView", "NtAlpcDeleteSecurityContext", "NtAlpcDisconnectPort", "NtAlpcImpersonateClientContainerOfPort", "NtAlpcImpersonateClientOfPort", "NtAlpcOpenSenderProcess", "NtAlpcOpenSenderThread", "NtAlpcQueryInformation", "NtAlpcQueryInformationMessage", "NtAlpcRevokeSecurityContext", "NtAlpcSendWaitReceivePort", "NtAlpcSetInformation", "NtAreMappedFilesTheSame", "NtAssignProcessToJobObject", "NtAssociateWaitCompletionPacket", "NtCallEnclave", "NtCancelIoFileEx", "NtCancelSynchronousIoFile", "NtCancelTimer2", "NtCancelWaitCompletionPacket", "NtCommitComplete", "NtCommitEnlistment", "NtCommitRegistryTransaction", "NtCommitTransaction", "NtCompactKeys", "NtCompareObjects", "NtCompareSigningLevels", "NtCompareTokens", "NtCompleteConnectPort", "NtCompressKey", "NtConnectPort", "NtContinueEx", "NtConvertBetweenAuxiliaryCounterAndPerformanceCounter", "NtCreateCrossVmEvent", "NtCreateCrossVmMutant", "NtCreateDebugObject", "NtCreateDirectoryObject", "NtCreateDirectoryObjectEx", "NtCreateEnclave", "NtCreateEnlistment", "NtCreateEventPair", "NtCreateIRTimer", "NtCreateIoCompletion", "NtCreateJobObject", "NtCreateJobSet", "NtCreateKeyTransacted", "NtCreateKeyedEvent", "NtCreateLowBoxToken", "NtCreateMailslotFile", "NtCreateMutant", "NtCreateNamedPipeFile", "NtCreatePagingFile", "NtCreatePartition", "NtCreatePort", "NtCreatePrivateNamespace", "NtCreateProcess", "NtCreateProfile", "NtCreateProfileEx", "NtCreateRegistryTransaction", "NtCreateResourceManager", "NtCreateSectionEx", "NtCreateSemaphore", "NtCreateSymbolicLinkObject", "NtCreateThreadEx", "NtCreateTimer", "NtCreateTimer2", "NtCreateToken", "NtCreateTokenEx", "NtCreateTransaction", "NtCreateTransactionManager", "NtCreateUserProcess", "NtCreateWaitCompletionPacket", "NtCreateWaitablePort", "NtCreateWnfStateName", "NtCreateWorkerFactory", "NtDebugActiveProcess", "NtDebugContinue", "NtDeleteAtom", "NtDeleteBootEntry", "NtDeleteDriverEntry", "NtDeleteFile", "NtDeleteKey", "NtDeleteObjectAuditAlarm", "NtDeletePrivateNamespace", "NtDeleteValueKey", "NtDeleteWnfStateData", "NtDeleteWnfStateName", "NtDirectGraphicsCall", "NtDisableLastKnownGood", "NtDisplayString", "NtDrawText", "NtEnableLastKnownGood", "NtEnumerateBootEntries", "NtEnumerateDriverEntries", "NtEnumerateSystemEnvironmentValuesEx", "NtEnumerateTransactionObject", "NtExtendSection", "NtFilterBootOption", "NtFilterToken", "NtFilterTokenEx", "NtFlushBuffersFileEx", "NtFlushInstallUILanguage", "NtFlushInstructionCache", "NtFlushKey", "NtFlushProcessWriteBuffers", "NtFlushVirtualMemory", "NtFlushWriteBuffer", "NtFreeUserPhysicalPages", "NtFreezeRegistry", "NtFreezeTransactions", "NtGetCachedSigningLevel", "NtGetCompleteWnfStateSubscription", "NtGetContextThread", "NtGetCurrentProcessorNumber", "NtGetCurrentProcessorNumberEx", "NtGetDevicePowerState", "NtGetMUIRegistryInfo", "NtGetNextProcess", "NtGetNextThread", "NtGetNlsSectionPtr", "NtGetNotificationResourceManager", "NtGetWriteWatch", "NtImpersonateAnonymousToken", "NtImpersonateThread", "NtInitializeEnclave", "NtInitializeNlsFiles", "NtInitializeRegistry", "NtInitiatePowerAction", "NtIsSystemResumeAutomatic", "NtIsUILanguageComitted", "NtListenPort", "NtLoadDriver", "NtLoadEnclaveData", "NtLoadKey", "NtLoadKey2", "NtLoadKeyEx", "NtLockFile", "NtLockProductActivationKeys", "NtLockRegistryKey", "NtLockVirtualMemory", "NtMakePermanentObject", "NtMakeTemporaryObject", "NtManageHotPatch", "NtManagePartition", "NtMapCMFModule", "NtMapUserPhysicalPages", "NtMapViewOfSectionEx", "NtModifyBootEntry", "NtModifyDriverEntry", "NtNotifyChangeDirectoryFile", "NtNotifyChangeDirectoryFileEx", "NtNotifyChangeKey", "NtNotifyChangeMultipleKeys", "NtNotifyChangeSession", "NtOpenEnlistment", "NtOpenEventPair", "NtOpenIoCompletion", "NtOpenJobObject", "NtOpenKeyEx", "NtOpenKeyTransacted", "NtOpenKeyTransactedEx", "NtOpenKeyedEvent", "NtOpenMutant", "NtOpenObjectAuditAlarm", "NtOpenPartition", "NtOpenPrivateNamespace", "NtOpenProcessToken", "NtOpenRegistryTransaction", "NtOpenResourceManager", "NtOpenSemaphore", "NtOpenSession", "NtOpenSymbolicLinkObject", "NtOpenThread", "NtOpenTimer", "NtOpenTransaction", "NtOpenTransactionManager", "NtPlugPlayControl", "NtPrePrepareComplete", "NtPrePrepareEnlistment", "NtPrepareComplete", "NtPrepareEnlistment", "NtPrivilegeCheck", "NtPrivilegeObjectAuditAlarm", "NtPrivilegedServiceAuditAlarm", "NtPropagationComplete", "NtPropagationFailed", "NtPssCaptureVaSpaceBulk", "NtPulseEvent", "NtQueryAuxiliaryCounterFrequency", "NtQueryBootEntryOrder", "NtQueryBootOptions", "NtQueryDebugFilterState", "NtQueryDirectoryFileEx", "NtQueryDirectoryObject", "NtQueryDriverEntryOrder", "NtQueryEaFile", "NtQueryFullAttributesFile", "NtQueryInformationAtom", "NtQueryInformationByName", "NtQueryInformationEnlistment", "NtQueryInformationJobObject", "NtQueryInformationPort", "NtQueryInformationResourceManager", "NtQueryInformationTransaction", "NtQueryInformationTransactionManager", "NtQueryInformationWorkerFactory", "NtQueryInstallUILanguage", "NtQueryIntervalProfile", "NtQueryIoCompletion", "NtQueryLicenseValue", "NtQueryMultipleValueKey", "NtQueryMutant", "NtQueryOpenSubKeys", "NtQueryOpenSubKeysEx", "NtQueryPortInformationProcess", "NtQueryQuotaInformationFile", "NtQuerySecurityAttributesToken", "NtQuerySecurityObject", "NtQuerySecurityPolicy", "NtQuerySemaphore", "NtQuerySymbolicLinkObject", "NtQuerySystemEnvironmentValue", "NtQuerySystemEnvironmentValueEx", "NtQuerySystemInformationEx", "NtQueryTimerResolution", "NtQueryWnfStateData", "NtQueryWnfStateNameInformation", "NtQueueApcThreadEx", "NtRaiseException", "NtRaiseHardError", "NtReadOnlyEnlistment", "NtRecoverEnlistment", "NtRecoverResourceManager", "NtRecoverTransactionManager", "NtRegisterProtocolAddressInformation", "NtRegisterThreadTerminatePort", "NtReleaseKeyedEvent", "NtReleaseWorkerFactoryWorker", "NtRemoveIoCompletionEx", "NtRemoveProcessDebug", "NtRenameKey", "NtRenameTransactionManager", "NtReplaceKey", "NtReplacePartitionUnit", "NtReplyWaitReplyPort", "NtRequestPort", "NtResetEvent", "NtResetWriteWatch", "NtRestoreKey", "NtResumeProcess", "NtRevertContainerImpersonation", "NtRollbackComplete", "NtRollbackEnlistment", "NtRollbackRegistryTransaction", "NtRollbackTransaction", "NtRollforwardTransactionManager", "NtSaveKey", "NtSaveKeyEx", "NtSaveMergedKeys", "NtSecureConnectPort", "NtSerializeBoot", "NtSetBootEntryOrder", "NtSetBootOptions", "NtSetCachedSigningLevel", "NtSetCachedSigningLevel2", "NtSetContextThread", "NtSetDebugFilterState", "NtSetDefaultHardErrorPort", "NtSetDefaultLocale", "NtSetDefaultUILanguage", "NtSetDriverEntryOrder", "NtSetEaFile", "NtSetHighEventPair", "NtSetHighWaitLowEventPair", "NtSetIRTimer", "NtSetInformationDebugObject", "NtSetInformationEnlistment", "NtSetInformationJobObject", "NtSetInformationKey", "NtSetInformationResourceManager", "NtSetInformationSymbolicLink", "NtSetInformationToken", "NtSetInformationTransaction", "NtSetInformationTransactionManager", "NtSetInformationVirtualMemory", "NtSetInformationWorkerFactory", "NtSetIntervalProfile", "NtSetIoCompletion", "NtSetIoCompletionEx", "NtSetLdtEntries", "NtSetLowEventPair", "NtSetLowWaitHighEventPair", "NtSetQuotaInformationFile", "NtSetSecurityObject", "NtSetSystemEnvironmentValue", "NtSetSystemEnvironmentValueEx", "NtSetSystemInformation", "NtSetSystemPowerState", "NtSetSystemTime", "NtSetThreadExecutionState", "NtSetTimer2", "NtSetTimerEx", "NtSetTimerResolution", "NtSetUuidSeed", "NtSetVolumeInformationFile", "NtSetWnfProcessNotificationEvent", "NtShutdownSystem", "NtShutdownWorkerFactory", "NtSignalAndWaitForSingleObject", "NtSinglePhaseReject", "NtStartProfile", "NtStopProfile", "NtSubscribeWnfStateChange", "NtSuspendProcess", "NtSuspendThread", "NtSystemDebugControl", "NtTerminateEnclave", "NtTerminateJobObject", "NtTestAlert", "NtThawRegistry", "NtThawTransactions", "NtTraceControl", "NtTranslateFilePath", "NtUmsThreadYield", "NtUnloadDriver", "NtUnloadKey", "NtUnloadKey2", "NtUnloadKeyEx", "NtUnlockFile", "NtUnlockVirtualMemory", "NtUnmapViewOfSectionEx", "NtUnsubscribeWnfStateChange", "NtUpdateWnfStateData", "NtVdmControl", "NtWaitForAlertByThreadId", "NtWaitForDebugEvent", "NtWaitForKeyedEvent", "NtWaitForWorkViaWorkerFactory", "NtWaitHighEventPair", "NtWaitLowEventPair", "NtLoadKey3" };

void data::initialize()
{
	for (auto i = 0; i < sizeof(windows_20h2_syscalls) / sizeof(windows_20h2_syscalls[0]); i++)
	{
		auto call = std::make_shared<syscall_t>(windows_20h2_syscalls[i]);
		
		if (!call->get_address())
		{
			continue;
		}

		syscall_data.push_back(call);
	}
}