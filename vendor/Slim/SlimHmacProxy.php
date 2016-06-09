<?php
/**
 * OSTİM TEKNOLOJİ Framework 
 *
 * @link      https://github.com/corner82/slim_test for the canonical source repository
 * @copyright Copyright (c) 2015 OSTİM TEKNOLOJİ (http://www.ostim.com.tr)
 * @license   
 */


namespace vendor\Slim;

class SlimHmacProxy extends \vendor\Proxy\Proxy {

    /**
     * a mapping array for related functions and proxy calls
     * to be executed
     * @var array()
     */
    protected $redirectMap = array('getReports_test' => 'restApiDefaultCall',
                                    'getDynamicForm_test' => 'restApiDefaultCall',

        //** leftnavigation ----------------------
                                    'pkDelete_leftnavigation' => 'restApiDefaultCall',
                                    'pkGetAll_leftnavigation' => 'restApiDefaultCall',
                                    'pkInsert_leftnavigation' => 'restApiDefaultCall',
                                    'pkUpdate_leftnavigation' => 'restApiDefaultCall',
                                    'pkFillGrid_leftnavigation' => 'restApiDefaultCall',                                    
                                    'pkGetLeftMenu_leftnavigation' => 'restApiDefaultCall',
                                    'pkFillGridForAdmin_leftnavigation' => 'restApiDefaultCall',
                                    'pkFillForAdminTree_leftnavigation' => 'restApiDefaultCall',
                                    'pkUpdateMakeActiveOrPassive_leftnavigation' => 'restApiDefaultCall',        
        
      
       
        //**---- leftnavigation -------------------
        //** syssectors ----------------------
                                    'pkDelete_syssectors' => 'restApiDefaultCall',
                                    'pkGetAll_syssectors' => 'restApiDefaultCall',
                                    'pkInsert_syssectors' => 'restApiDefaultCall',
                                    'pkUpdate_syssectors' => 'restApiDefaultCall',
                                    'pkFillGrid_syssectors' => 'restApiDefaultCall',                                    
                                    'fillComboBox_syssectors' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate' => 'restApiDefaultCall',
                                    'pkFillTextLanguageTemplate' => 'restApiDefaultCall',
        
           
         //**---- syssectors -------------------
        
         //** infoUsers ----------------------
                                    'pkDelete_infoUsers' => 'restApiDefaultCall',
                                    'pkGetAll_infoUsers' => 'restApiDefaultCall',
                                    'pkInsert_infoUsers' => 'restApiDefaultCall',
                                    'tempInsert_infoUsers' => 'restApiDefaultCall',
                                    'pkUpdate_infoUsers' => 'restApiDefaultCall',
                                    'pkFillGrid_infoUsers' => 'restApiDefaultCall',                                    
                                    'pkDeletedAct_infoUsers' => 'restApiDefaultCall',
                                    'pktempUpdate_infoUsers' => 'restApiDefaultCall',
                            
                                    
         //**---- infoUsers -------------------
                                        
         //** syscountrys ----------------------
                                    'pkDelete_syscountrys' => 'restApiDefaultCall',
                                    'pkGetAll_syscountrys' => 'restApiDefaultCall',
                                    'pkInsert_syscountrys' => 'restApiDefaultCall',
                                    'pkUpdate_syscountrys' => 'restApiDefaultCall',
                                    'pkFillGrid_syscountrys' => 'restApiDefaultCall',                                    
                                    'fillComboBox_syscountrys' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate_syscountrys' => 'restApiDefaultCall',
        
     
                                    
         //**---- syscountrys -------------------
        
        //** syscity ----------------------
                                    'pkDelete_syscity' => 'restApiDefaultCall',
                                    'pkGetAll_syscity' => 'restApiDefaultCall',
                                    'pkInsert_syscity' => 'restApiDefaultCall',
                                    'pkUpdate_syscity' => 'restApiDefaultCall',
                                    'pkFillGrid_syscity' => 'restApiDefaultCall',                                    
                                    'fillComboBox_syscity' => 'restApiDefaultCall',   
                                    'pkInsertLanguageTemplate_syscity' => 'restApiDefaultCall',  
        
        
                                    
         //**---- syscity -------------------
         //** syslanguage ----------------------
                                    'pkDelete_syslanguage' => 'restApiDefaultCall',
                                    'pkGetAll_syslanguage' => 'restApiDefaultCall',
                                    'pkInsert_syslanguage' => 'restApiDefaultCall',
                                    'pkUpdate_syslanguage' => 'restApiDefaultCall',
                                    'pkFillGrid_syslanguage' => 'restApiDefaultCall',                                    
                                    'fillComboBox_syslanguage' => 'restApiDefaultCall',    
                                    
         //**---- syslanguage -------------------
          //** sysborough ----------------------
                                    'pkDelete_sysborough' => 'restApiDefaultCall',
                                    'pkGetAll_sysborough' => 'restApiDefaultCall',
                                    'pkInsert_sysborough' => 'restApiDefaultCall',
                                    'pkUpdate_sysborough' => 'restApiDefaultCall',
                                    'pkFillGrid_sysborough' => 'restApiDefaultCall',                                    
                                    'fillComboBox_sysborough' => 'restApiDefaultCall',  
                                    'pkInsertLanguageTemplate_sysborough' => 'restApiDefaultCall',  
         //**---- sysborough -------------------       
        
           //** sysvillage ----------------------
                                    'pkDelete_sysvillage' => 'restApiDefaultCall',
                                    'pkGetAll_sysvillage' => 'restApiDefaultCall',
                                    'pkInsert_sysvillage' => 'restApiDefaultCall',
                                    'pkUpdate_sysvillage' => 'restApiDefaultCall',
                                    'pkFillGrid_sysvillage' => 'restApiDefaultCall',                                    
                                    'fillComboBox_sysvillage' => 'restApiDefaultCall',  
                                    'pkInsertLanguageTemplate_sysvillage' => 'restApiDefaultCall',   
                        
         //**---- sysvillage -------------------   
        
         //** blLoginLogout ----------------------
                                    'pkDelete_blLoginLogout' => 'restApiDefaultCall',
                                    'pkGetAll_blLoginLogout' => 'restApiDefaultCall',
                                    'pkInsert_blLoginLogout' => 'restApiDefaultCall',
                                    'pkUpdate_blLoginLogout' => 'restApiDefaultCall',
                                    'pkControl_blLoginLogout' => 'restApiDefaultCall',
                                    'pkLoginControl_blLoginLogout' => 'restApiDefaultCall',
                                    'pkGetPK_blLoginLogout' => 'restApiDefaultCall',  
                                    'pkSessionControl_blLoginLogout' => 'restApiDefaultCall',   
                                    'pkIsThere_blLoginLogout' => 'restApiDefaultCall',   
                                    'pkAllPkGeneratedFromPrivate_blLoginLogout' => 'restApiDefaultCall',  
                        
        
         //**---- blLoginLogout -------------------   
         //** infoFirmProfile ----------------------
                                    'pkDelete_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillComboBox_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkInsertLanguageTemplate_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillTextLanguageTemplate_infoFirmProfile' => 'restApiDefaultCall',
                            
                                    'pktempInsert_infoFirmProfile' => 'restApiDefaultCall',
        
                                    'pkFillCompanyLists_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillCompanyInfoEmployees_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillCompanyInfoReferences_infoFirmProfile' => 'restApiDefaultCall',        
                                    'pkFillCompanyInfoSocialedia_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillCompanyInfoCustomers_infoFirmProfile' => 'restApiDefaultCall', 
                                    'pkFillCompanyInfoProducts_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillCompanyInfoSectors_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkFillCompanyInfoBuildingNpk_infoFirmProfile' => 'restApiDefaultCall',
        
        
                                    'fillCompanyListsGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillCompanyInfoEmployeesGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillCompanyInfoSocialediaGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillCompanyInfoReferencesGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillCompanyInfoCustomersGuest_infoFirmProfile' => 'restApiDefaultCall', 
                                    'fillCompanyInfoProductsGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    'fillCompanyInfoSectorsGuest_infoFirmProfile' => 'restApiDefaultCall',
                                    
                                    'pkFillFirmFullVerbal_infoFirmProfile' => 'restApiDefaultCall',
                                    'pkGetFirmProfileConsultant_infoFirmProfile' => 'restApiDefaultCall',
         
                                    
         //**---- infoFirmProfile -------------------
         //** sysAclRoles ----------------------
                                    'pkDelete_sysAclRoles' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclRoles' => 'restApiDefaultCall',
                                    'pkInsert_sysAclRoles' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclRoles' => 'restApiDefaultCall',
                                    'pkUpdateChild_sysAclRoles' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclRoles' => 'restApiDefaultCall',                                    
                                    'pkFillComboBoxMainRoles_sysAclRoles' => 'restApiDefaultCall',   
                                    'pkFillComboBoxFullRoles_sysAclRoles' => 'restApiDefaultCall',  
                                    'pkFillComboBoxRoles_sysAclRoles' => 'restApiDefaultCall',  
        
         //**---- sysAclRoles -------------------  
         //** sysAclResources ----------------------
                                    'pkDelete_sysAclResources' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclResources' => 'restApiDefaultCall',
                                    'pkInsert_sysAclResources' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclResources' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclResources' => 'restApiDefaultCall',

                                    'pkFillComboBoxMainResources_sysAclResources' => 'restApiDefaultCall',   
                                    'pkFillComboBoxFullResources_sysAclResources' => 'restApiDefaultCall',  
     
         //**---- sysAclResources -------------------  
       //** sysAclPrivilege ----------------------
                                    'pkDelete_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkInsert_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclPrivilege' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclPrivilege' => 'restApiDefaultCall',                                    
                                    'pkFillComboBoxFullPrivilege_sysAclPrivilege' => 'restApiDefaultCall',  
     
         //**---- sysAclPrivilege ------------------- 
            //** SysAclRrpMap ----------------------
                                    'pkDelete_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkGetAll_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkInsert_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkUpdate_sysAclRrpMap' => 'restApiDefaultCall',
                                    'pkFillGrid_sysAclRrpMap' => 'restApiDefaultCall',                                    
                                    'pkFillRrpMap_sysAclRrpMap' => 'restApiDefaultCall',  
     
         //**---- SysAclRrpMap -------------------    
         //** sysSpecificDefinitions ----------------------
                                    'fillMainDefinitions_sysSpecificDefinitions' => 'restApiDefaultCall',
                                    'fillFullDefinitions_sysSpecificDefinitions' => 'restApiDefaultCall',
                                    'fillCommunicationsTypes_sysSpecificDefinitions' => 'restApiDefaultCall',
                                    'fillBuildingType_sysSpecificDefinitions' => 'restApiDefaultCall',
                                    'fillOwnershipType_sysSpecificDefinitions' => 'restApiDefaultCall',
                                    'fillPersonnelTypes_sysSpecificDefinitions' => 'restApiDefaultCall',                                  
                                    'fillAddressTypes_sysSpecificDefinitions' => 'restApiDefaultCall',                                  
        
     
         //**---- sysSpecificDefinitions -------------------    
         //** infoUsersCommunications ----------------------
                                    'pkDelete_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pkGetAll_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pkInsert_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pkUpdate_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pkFillGrid_infoUsersCommunications' => 'restApiDefaultCall',                                    
                                    'pkDeletedAct_infoUsersCommunications' => 'restApiDefaultCall',
                                    'fillUserCommunicationsTypes_infoUsersCommunications' => 'restApiDefaultCall',
                                    'fillGridSingular_infoUsersCommunications' => 'restApiDefaultCall',                                   
                                   
                                    'pktempInsert_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pktempUpdate_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pktempDeletedAct_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pktempFillUserCommunicationsTypes_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pktempFillGridSingular_infoUsersCommunications' => 'restApiDefaultCall',
                                    'pktempFillGridSingularRowTotalCount_infoUsersCommunications' => 'restApiDefaultCall',
                                    
        
        
         //**---- infoUsersCommunications -------------------
        
        //** InfoUsersAddresses ----------------------
                                    'pkDelete_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkGetAll_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkInsert_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkUpdate_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkFillGrid_infoUsersAddresses' => 'restApiDefaultCall',                                    
                                    'pkDeletedAct_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkFillUserAddressesTypes_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pkfillGridSingular_infoUsersAddresses' => 'restApiDefaultCall',                                    
                                           
                                    'pktempInsert_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pktempUpdate_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pktempDeletedAct_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pktempFillUserAddressesTypes_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pktempFillGridSingular_infoUsersAddresses' => 'restApiDefaultCall',
                                    'pktempFillGridSingularRowTotalCount_infoUsersAddresses' => 'restApiDefaultCall',                                    
        
        
         //**---- InfoUsersAddresses -------------------
         //** BlActivationReport ----------------------
                                    'pkDelete_blActivationReport' => 'restApiDefaultCall',
                                    'pkGetAll_blActivationReport' => 'restApiDefaultCall',
                                    'pkInsert_blActivationReport' => 'restApiDefaultCall',
                                    'pkUpdate_blActivationReport' => 'restApiDefaultCall',
        
                                    'pkGetConsultantOperation_blActivationReport' => 'restApiDefaultCall',
                                    'getAllFirmCount_blActivationReport' => 'restApiDefaultCall',
                                    'pkGetConsultantFirmCount_blActivationReport' => 'restApiDefaultCall',
                                    'pkGetConsultantUpDashBoardCount_blActivationReport' => 'restApiDefaultCall',
                                    'pkGetConsWaitingForConfirm_blActivationReport' => 'restApiDefaultCall',
                                     
         
        
         //**---- BlActivationReport -------------------   
      
        //** sysOsbConsultants ----------------------
                                    'pkDelete_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkGetAll_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkInsert_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkUpdate_sysOsbConsultants' => 'restApiDefaultCall',
        
                                    'pkGetConsPendingFirmProfile_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkGetConsPendingFirmProfilertc_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkGetConsConfirmationProcessDetails_sysOsbConsultants' => 'restApiDefaultCall',
                                    'pkGetAllFirmCons_sysOsbConsultants' => 'restApiDefaultCall',
                         
        
         //**---- sysOsbConsultants -------------------   
        
         //** sysOperationTypes ----------------------
                                    'pkDelete_sysOperationTypes' => 'restApiDefaultCall',
                                    'pkGetAll_sysOperationTypes' => 'restApiDefaultCall',
                                    'pkInsert_sysOperationTypes' => 'restApiDefaultCall',
                                    'pkUpdate_sysOperationTypes' => 'restApiDefaultCall',
                                    'pkFillGrid_sysOperationTypes' => 'restApiDefaultCall',                                    
                                    
                                    'pkFillConsultantOperationsDropDown_sysOperationTypes' => 'restApiDefaultCall',
                                   
        
         //**---- sysOperationTypes -------------------   
        
        //** sysOperationTypesTools ----------------------
                                    'pkDelete_sysOperationTypesTools' => 'restApiDefaultCall',
                                    'pkGetAll_sysOperationTypesTools' => 'restApiDefaultCall',
                                    'pkInsert_sysOperationTypesTools' => 'restApiDefaultCall',
                                    'pkUpdate_sysOperationTypesTools' => 'restApiDefaultCall',
                                    'pkFillGrid_sysOperationTypesTools' => 'restApiDefaultCall',                                    
                                    
                                    'pkFillConsultantOperationsToolsDropDown_sysOperationTypesTools' => 'restApiDefaultCall',
                                   
        
         //**---- sysOperationTypesTools -------------------   
        
         
        //** InfoError ----------------------
                                    'pkDelete_infoError' => 'restApiDefaultCall',
                                    'pkGetAll_infoError' => 'restApiDefaultCall',
                                    'pkInsert_infoError' => 'restApiDefaultCall',
                                    'pkUpdate_infoError' => 'restApiDefaultCall',
                                    'pkFillGrid_infoError' => 'restApiDefaultCall',                                    


         //**---- InfoError -------------------   
        
         //** SysMachineToolGroups ----------------------
                                    'pkDelete_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkGetAll_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkInsert_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkUpdate_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMachineToolGroups' => 'restApiDefaultCall',                                    
        
                                    'pkFillMachineToolGroups_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkFillJustMachineToolGroups_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkFillMachineToolGroupsMachineProperties_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkFillJustMachineToolGroupsBootstrap_sysMachineToolGroups' => 'restApiDefaultCall',
                                    'pkFillJustMachineToolGroupsNotInProperty_sysMachineToolGroups' => 'restApiDefaultCall',
                                    
        


         //**---- SysMachineToolGroups -------------------   
        
       //** SysMachineTools ----------------------
                                    'pkDelete_sysMachineTools' => 'restApiDefaultCall',
                                    'pkGetAll_sysMachineTools' => 'restApiDefaultCall',
                                    'pkInsert_sysMachineTools' => 'restApiDefaultCall',
                                    'pkUpdate_sysMachineTools' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMachineTools' => 'restApiDefaultCall', 
                                    'pkGetMachineTools_sysMachineTools' => 'restApiDefaultCall',  
                                    'pkGetMachineProperities_sysMachineTools' => 'restApiDefaultCall',          
                                    'pkUpdateMakeActiveOrPassive_sysMachineTools' => 'restApiDefaultCall',        

         //**---- SysMachineTools -------------------   
         //** sysMachineToolPropertyDefinition ----------------------
                                    'pkDelete_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
                                    'pkGetAll_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
                                    'pkInsert_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
                                    'pkUpdate_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
        
                                    'pkFillMachineToolGroupPropertyDefinitions_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',
                                    'pkUpdateMakeActiveOrPassive_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',        
                                    'pkFillMachineGroupPropertyDefinitions_sysMachineToolPropertyDefinition' => 'restApiDefaultCall', 
                                    'pkDeletePropertyMachineGroup_sysMachineToolPropertyDefinition' => 'restApiDefaultCall',                                    
        
        
        
         //**---- sysMachineToolPropertyDefinition -------------------   
         //** SysMachineToolProperties ----------------------
                                    'pkDelete_sysMachineToolProperties' => 'restApiDefaultCall',
                                    'pkGetAll_sysMachineToolProperties' => 'restApiDefaultCall',
                                    'pkInsert_sysMachineToolProperties' => 'restApiDefaultCall',
                                    'pkUpdate_sysMachineToolProperties' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMachineToolProperties' => 'restApiDefaultCall',
                                    'pkFillMachineToolFullProperties_sysMachineToolProperties' => 'restApiDefaultCall',
        
                                  
        
         //**---- SysMachineToolProperties -------------------   
        //** SysUnits ----------------------
                                    'pkDelete_sysUnits' => 'restApiDefaultCall',                                    
                                    'pkInsert_sysUnits' => 'restApiDefaultCall',
                                    'pkUpdate_sysUnits' => 'restApiDefaultCall',
                                    'pkGetAll_sysUnits' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_sysUnits' => 'restApiDefaultCall',                                    
                                    'pkGetUnits_sysUnits' => 'restApiDefaultCall',
                                    'pkFillUnitsTree_sysUnits' => 'restApiDefaultCall',   
                                    'pkUpdateMakeActiveOrPassive_sysUnits' => 'restApiDefaultCall',        
        
                                 
         //**---- SysUnits -------------------   
         
        //** sysUnitSystems ----------------------
                                    'pkDelete_sysUnitSystems' => 'restApiDefaultCall',                                    
                                    'pkInsert_sysUnitSystems' => 'restApiDefaultCall',
                                    'pkUpdate_sysUnitSystems' => 'restApiDefaultCall',
                                    'pkGetAll_sysUnitSystems' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_sysUnitSystems' => 'restApiDefaultCall',                                    
                                    'pkGetUnitSystems_sysUnitSystems' => 'restApiDefaultCall',
                                    'pkFillUnitSystemsTree_sysUnitSystems' => 'restApiDefaultCall',        
        
                                 
         //**---- sysUnitSystems -------------------   
        

        
        //** InfoFirmMachineTool ----------------------
                                    'pkDelete_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoFirmMachineTool' => 'restApiDefaultCall',
                                    
                                    'pkFillSingularFirmMachineTools_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillSingularFirmMachineToolsRtc_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillUsersFirmMachines_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillUsersFirmMachineProperties_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillFirmMachineGroupsCounts_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillUsersFirmMachinesNpk_infoFirmMachineTool' => 'restApiDefaultCall',
                                    'pkFillAllCompanyMachineLists_infoFirmMachineTool' => 'restApiDefaultCall',
        
        
        
        
                                         
         //**---- InfoFirmMachineTool -------------------   
        //** SysNaceCodes ----------------------
                                    'pkDelete_sysNaceCodes' => 'restApiDefaultCall',
                                    'pkGetAll_sysNaceCodes' => 'restApiDefaultCall',
                                    'pkInsert_sysNaceCodes' => 'restApiDefaultCall',
                                    'pkUpdate_sysNaceCodes' => 'restApiDefaultCall',
                                    'pkFillGrid_sysNaceCodes' => 'restApiDefaultCall',
                                    'pkFillNaceCodes_sysNaceCodes' => 'restApiDefaultCall',                                     
                                         
        //**---- SysNaceCodes -------------------   
        //** HstryLogin ----------------------                                    
                                    'pkGetAll_hstryLogin' => 'restApiDefaultCall',
                                    'pkInsert_hstryLogin' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_hstryLogin' => 'restApiDefaultCall',
                                         
        //**---- HstryLogin -------------------    
        
         //** BlAdminActivationReport ----------------------
                                  
                                    'pkGetAll_blAdminActivationReport' => 'restApiDefaultCall',
                                    'pkInsert_blAdminActivationReport' => 'restApiDefaultCall',                                  
        
                                    'pkGetConsultantOperation_blAdminActivationReport' => 'restApiDefaultCall',
                                    'pkGetAllConsultantFirmCount_blAdminActivationReport' => 'restApiDefaultCall',
                                    'pkGetUpDashBoardCount_blAdminActivationReport' => 'restApiDefaultCall',
                                    'pkGetDashBoardHighCharts_blAdminActivationReport' => 'restApiDefaultCall',                                     
         
        
         //**---- BlAdminActivationReport -------------------  
        
        
       //** LogConnection ----------------------
                                  
                                    'pkGetAll_logConnection' => 'restApiDefaultCall',
                                    'pkInsert_logConnection' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_logConnection' => 'restApiDefaultCall',
                                    
         //**---- LogConnection -------------------   
         //** logServices ----------------------
                                   
                                    'pkGetAll_logServices' => 'restApiDefaultCall',
                                    'pkInsert_logServices' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_logServices' => 'restApiDefaultCall',
                                    
         //**---- logServices -------------------   
       
         //** LogConsultant ----------------------
                                  
                                    'pkGetAll_logConsultant' => 'restApiDefaultCall',
                                    'pkInsert_logConsultant' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_logConsultant' => 'restApiDefaultCall',
                                    
         //**---- LogConsultant -------------------   
       
        
        
        //** LogAdmin ----------------------
                                  
                                    'pkGetAll_logAdmin' => 'restApiDefaultCall',
                                    'pkInsert_logAdmin' => 'restApiDefaultCall',                                    
                                    'pkFillGrid_logAdmin' => 'restApiDefaultCall',
                                    
         //**---- LogAdmin -------------------   
       
        //** sysUnspscCodes ----------------------                                    
                                    'pkGetAll_sysUnspscCodes' => 'restApiDefaultCall',                                   
                                    
                                    'pkFillGrid_sysUnspscCodes' => 'restApiDefaultCall',                                    
                                    'pkGetUnspscCodes_sysUnspscCodes' => 'restApiDefaultCall',
                                    'pkFillUnspscCodesTree_sysUnspscCodes' => 'restApiDefaultCall',
         
         //**---- sysUnspscCodes -------------------   
        //** SysCertifications ----------------------
                                    'pkDelete_sysCertifications' => 'restApiDefaultCall',
                                    'pkGetAll_sysCertifications' => 'restApiDefaultCall',
                                    'pkInsert_sysCertifications' => 'restApiDefaultCall',
                                    'pkUpdate_sysCertifications' => 'restApiDefaultCall',
                                    'pkFillGrid_sysCertifications' => 'restApiDefaultCall',
                                    'pkFillNaceCodes_sysCertifications' => 'restApiDefaultCall',                                     
                                         
        //**---- SysCertifications -------------------    
        
        //** InfoFirmReferences ----------------------
                                    'pkDelete_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkFillGridSingular_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkFillWithReference_infoFirmReferences' => 'restApiDefaultCall',
                                    'pkFillBeReferenced_infoFirmReferences' => 'restApiDefaultCall',
        
         //**---- InfoFirmReferences -------------------
        
         //** SysProductionTypes ----------------------
                                    'pkDelete_sysProductionTypes' => 'restApiDefaultCall',
                                    'pkGetAll_sysProductionTypes' => 'restApiDefaultCall',
                                    'pkInsert_sysProductionTypes' => 'restApiDefaultCall',
                                    'pkUpdate_sysProductionTypes' => 'restApiDefaultCall',
                                    'pkFillGrid_sysProductionTypes' => 'restApiDefaultCall',
                                    'pkFillProductionTypesTree_sysProductionTypes' => 'restApiDefaultCall',   
                                    'pkUpdateMakeActiveOrPassive_sysProductionTypes' => 'restApiDefaultCall',        
        
                                         
        //**---- SysProductionTypes -------------------    
         //** infoFirmUsers ----------------------
                                    'pkDelete_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkDeletedAct_infoFirmUsers' => 'restApiDefaultCall',
                                    
                                    'pkFillGridSingular_infoFirmUsers' => 'restApiDefaultCall',                                                                        
                                    'pkFillGridSingularNpk_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkUpdateMakeActiveOrPassive_infoFirmUsers' => 'restApiDefaultCall',
                                    'pkFillCompanyUsersSocialMediaNpk_infoFirmUsers' => 'restApiDefaultCall',        
                                        
         //**---- infoFirmUsers -------------------   
        
         //** SysMachineToolDefinitionAttribute ----------------------
                                    'pkDelete_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',
                                    'pkGetAll_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',
                                    'pkInsert_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',
                                    'pkUpdate_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',
                                    
                                    'pkFillMachineToolDefinitionsAttributes_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',   
                                    'pkUpdateMakeActiveOrPassive_sysMachineToolDefinitionAttribute' => 'restApiDefaultCall',        
                                                 
        //**---- SysMachineToolDefinitionAttribute -------------------    
        //** InfoUsersSocialmedia ----------------------
                                    'pkDelete_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    'pkGetAll_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    'pkInsert_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    'pkUpdate_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    'pkFillGrid_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    
                                    'pkFillSingularUsersSocialMedia_infoUsersSocialmedia' => 'restApiDefaultCall',   
                                    'pkUpdateMakeActiveOrPassive_infoUsersSocialmedia' => 'restApiDefaultCall',        
                                    'pkDeletedAct_infoUsersSocialmedia' => 'restApiDefaultCall',
                                    'pkFillCompanyUsersSocialMediaNpk_infoUsersSocialmedia' => 'restApiDefaultCall',
        
        
        //**---- infoUsersSocialmedia -------------------    
        //** InfoFirmVerbal ----------------------
                                    'pkDelete_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkcpkInsert_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkcpkUpdate_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmVerbal' => 'restApiDefaultCall',                                    
                                    
                                    'pkDeletedAct_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkFillUsersFirmVerbalNpk_infoFirmVerbal' => 'restApiDefaultCall',
                                    'fillUsersFirmVerbalNpkGuest_infoFirmVerbal' => 'restApiDefaultCall',
                                    'pkGetFirmVerbalConsultant_infoFirmVerbal' => 'restApiDefaultCall',        
                                    'sendMailConsultant_infoFirmVerbal' => 'restApiDefaultCall', 
        
        
        //**---- InfoFirmVerbal ------------------- 
        //** InfoFirmUserDescForCompany ----------------------
                                    'pkDelete_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmUserDescForCompany' => 'restApiDefaultCall',                                    
                                    
                                    'pkDeletedAct_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'pkFillUsersDescForFirmVerbalNpk_infoFirmUserDescForCompany' => 'restApiDefaultCall',
                                    'fillUsersDescForFirmVerbalNpkGuest_infoFirmUserDescForCompany' => 'restApiDefaultCall',
        
        //**---- InfoFirmUserDescForCompany ------------------- 
        
        //** SysSocialMedia ----------------------
                                    'pkDelete_sysSocialMedia' => 'restApiDefaultCall',
                                    'pkGetAll_sysSocialMedia' => 'restApiDefaultCall',
                                    'pkInsert_sysSocialMedia' => 'restApiDefaultCall',
                                    'pkUpdate_sysSocialMedia' => 'restApiDefaultCall',
                                    'pkFillGrid_sysSocialMedia' => 'restApiDefaultCall',                                    
                                    
                                    'pkUpdateMakeActiveOrPassive_sysSocialMedia' => 'restApiDefaultCall',        
                                    'pkFillSocicalMediaDdList_sysSocialMedia' => 'restApiDefaultCall', 
                                    
        
        //**---- SysSocialMedia ------------------- 
          
        //** InfoFirmSocialmedia ----------------------
                                    'pkDelete_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkUpdateMakeActiveOrPassive_infoFirmSocialmedia' => 'restApiDefaultCall',
                                    'pkFillSingularFirmSocialMedia_infoFirmSocialmedia' => 'restApiDefaultCall', 
                                    
        
        //**---- InfoFirmSocialmedia -------------------  
           
        //** InfoFirmAddress ----------------------
                                    'pkDelete_infoFirmAddress' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmAddress' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmAddress' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmAddress' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmAddress' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmAddress' => 'restApiDefaultCall',                                    
                                    'pkFillSingularFirmAddress_infoFirmAddress' => 'restApiDefaultCall', 
                                    'pkFillUsersFirmAddressNpk_infoFirmAddress' => 'restApiDefaultCall', 
                                    'FillUsersFirmAddressNpkQuest_infoFirmAddress' => 'restApiDefaultCall', 
                                            
        //**---- InfoFirmAddress -------------------  
        //** SysManufacturer ----------------------
                                    'pkDelete_sysManufacturer' => 'restApiDefaultCall',
                                    'pkGetAll_sysManufacturer' => 'restApiDefaultCall',
                                    'pkInsert_sysManufacturer' => 'restApiDefaultCall',
                                    'pkUpdate_sysManufacturer' => 'restApiDefaultCall',
                                    'pkFillGrid_sysManufacturer' => 'restApiDefaultCall',                                    
                                    
                                    'pkUpdateMakeActiveOrPassive_sysManufacturer' => 'restApiDefaultCall',        
                                    'pkFillManufacturerList_sysManufacturer' => 'restApiDefaultCall', 
        //**---- SysManufacturer ------------------- 
         //** SysMailServer ----------------------
                                    'pkDelete_sysMailServer' => 'restApiDefaultCall',
                                    'pkGetAll_sysMailServer' => 'restApiDefaultCall',
                                    'pkInsert_sysMailServer' => 'restApiDefaultCall',
                                    'pkUpdate_sysMailServer' => 'restApiDefaultCall',
                                    'pkFillGrid_sysMailServer' => 'restApiDefaultCall',                                    
                                    
                                    'pkUpdateMakeActiveOrPassive_sysMailServer' => 'restApiDefaultCall',        
                                    'pkFillMailServerList_sysMailServer' => 'restApiDefaultCall', 
        //**---- SysMailServer ------------------- 
        
        //** infoFirmProducts ----------------------
                                    'pkDelete_infoFirmProducts' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmProducts' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmProducts' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmProducts' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmProducts' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmProducts' => 'restApiDefaultCall',                                    
                                    'pkFillFirmProductsNpk_infoFirmProducts' => 'restApiDefaultCall', 
                                    'pkFillFirmProductsNpkQuest_infoFirmProducts' => 'restApiDefaultCall', 
                                    'pkFillFirmProductsGtip_infoFirmProducts' => 'restApiDefaultCall', 
                                            
        //**---- infoFirmProducts -------------------  
        //** InfoFirmProductsServices ----------------------
                                    'pkDelete_infoFirmProductsServices' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmProductsServices' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmProductsServices' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmProductsServices' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmProductsServices' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmProductsServices' => 'restApiDefaultCall',                                    
                                    'pkFillFirmProductsServicesNpk_infoFirmProductsServices' => 'restApiDefaultCall', 
                                    'FillFirmProductsServicesNpkQuest_infoFirmProductsServices' => 'restApiDefaultCall', 
                                    'pkUpdateMakeActiveOrPassive_infoFirmProductsServices' => 'restApiDefaultCall',        
                                            
        //**---- InfoFirmProductsServices -------------------  
        //** InfoFirmCertificate ----------------------
                                    'pkDelete_infoFirmCertificate' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmCertificate' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmCertificate' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmCertificate' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmCertificate' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmCertificate' => 'restApiDefaultCall',                                    
                                    'pkFillFirmCertificateNpk_infoFirmCertificate' => 'restApiDefaultCall', 
                                    'FillFirmCertificateNpkQuest_infoFirmCertificate' => 'restApiDefaultCall', 
                                    'pkUpdateMakeActiveOrPassive_infoFirmCertificate' => 'restApiDefaultCall',        
                                            
        //**---- InfoFirmCertificate -------------------  
        
        //** InfoFirmQuality ----------------------
                                    'pkDelete_infoFirmQuality' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmQuality' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmQuality' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmQuality' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmQuality' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmQuality' => 'restApiDefaultCall',
                                    'pkFillFirmQualityCertificateNpk_infoFirmQuality' => 'restApiDefaultCall', 
                                    'FillFirmQualityCertificateNpkQuest_infoFirmQuality' => 'restApiDefaultCall', 
                                    'pkUpdateMakeActiveOrPassive_infoFirmQuality' => 'restApiDefaultCall',        
                                            
        //**---- InfoFirmQuality -------------------  
         //** infoFirmSectoral ----------------------
                                    'pkDelete_infoFirmSectoral' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmSectoral' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmSectoral' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmSectoral' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmSectoral' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmSectoral' => 'restApiDefaultCall',
                                    'pkFillFirmSectorNpk_infoFirmSectoral' => 'restApiDefaultCall', 
                                    'FillFirmSectorNpkQuest_infoFirmSectoral' => 'restApiDefaultCall', 
                                    'pkUpdateMakeActiveOrPassive_infoFirmSectoral' => 'restApiDefaultCall',
                                            
        //**---- infoFirmSectoral -------------------   
         //** InfoFirmLanguageInfo ----------------------
                                    'pkDelete_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkGetAll_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkInsert_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkUpdate_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkFillGrid_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    
                                    'pkDeletedAct_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkFillFirmLanguageNpk_infoFirmLanguageInfo' => 'restApiDefaultCall', 
                                    'FillFirmLanguageNpkQuest_infoFirmLanguageInfo' => 'restApiDefaultCall', 
                                    'pkUpdateMakeActiveOrPassive_infoFirmLanguageInfo' => 'restApiDefaultCall',
                                    'pkFillFindFirmLanguageId_infoFirmLanguageInfo' => 'restApiDefaultCall', 
        //**---- InfoFirmLanguageInfo -------------------   
        
        
    );

    /**
     * hmac object
     * @var \vendor\hmac\Hmac
     */
    protected $hmacObj;
    
    /**
     * Dal object
     * @var \vendor\dal\Dal
     */
    protected $dalObject;

    /**
     * constructor 
     */
    public function __construct() {
        parent::__construct();
        $this->hmacObj = new \vendor\hmac\Hmac();
        $this->dalObject = new \vendor\dal\Dal();
    }

    /**
     * redirect to the service endpoint
     */
    public function redirect() {
        try {
            $execFunction = $this->resolveRedirectMap();
            $this->setEndPointByClosure();
            echo $this->$execFunction();
        } catch (\Exception $exc) {
            echo $exc->getTraceAsString();
        }
    }
    
     /**
      * 
      * @return boolean
      * @author Mustafa Zeynel Dağlı
      * @since version 0.3
      */
     public function servicePkRequired() {
         if($this->isServicePkRequired == null) {
             $params = $this->getRequestParams();
             if(substr(trim($params['url']),0,2) == 'pk' && 
                     substr(trim($params['url']),0,6) != 'pktemp') {
                $this->isServicePkRequired = true;
                return $this->isServicePkRequired ;
             }
             $this->isServicePkRequired = false;
             $this->isServicePkRequired;
         } else {
             return $this->isServicePkRequired;
         }
     }
       
    /**
     * Rest api 'GET' call (Curl lib)
     * function overriden
     * @author Mustafa Zeynel Dağlı
     * @version 0.2
     * @todo conside check if request is ssl encypted (https)
     */
    public function restApiDefaultCall() {

        /* $encrypt = new \vendor\Encrypt\EncryptManual('test');
          $encryptValue = $encrypt->encrypt_times(4, 'kullanici:sifre');
          //print_r('--'.$encryptValue.'--');
          $decryptValue = $encrypt->decrypt_times(4, $encryptValue);
          //print_r('??'.$decryptValue.'??'); */
        $this->servicePkRequired();
        $this->servicePkTempRequired();
        $this->serviceCpkRequired();
        $this->setEncryptClass();
        $params = null;
        $params = $this->getRequestParams();
        
        /**
         * controlling public key if public key is necessary for this service and
         * public key not found forwarder is in effect then making forward
         * @since version 0.3 06/01/2016
         */
        if(!isset($params['pk']) || $params['pk']==null) $this->publicKeyNotFoundRedirect();
        
        /**
         * controlling public temp key if public key is necessary for this service and
         * public temp key not found forwarder is in effect then making forward
         * @since version 0.3 27/01/2016
         */
        if(!isset($params['pktemp']) || $params['pktemp']==null) $this->publicKeyTempNotFoundRedirect();
        
        /**
         * controlling company public key if company public key is necessary for this service and
         * public temp key not found forwarder is in effect then making forward
         * @since version 0.3 27/01/2016
         */
        if(!isset($params['cpk']) || $params['cpk']==null) $this->publicKeyCompanyNotFoundRedirect();
        
        /**
         * getting public key if user registered    
         * @author Mustafa Zeynel Dağlı
         * @since 06/01/2016 version 0.3
         */
        if(isset($params['pk']) &&  $this->isServicePkRequired) {
            $resultSet = $this->dalObject->pkIsThere(array('pk' => $params['pk']));
            if(!isset($resultSet['resultSet'][0]['?column?'])) $this->userNotRegisteredRedirect ();
        }
        
        /**
         * public  key processes wrapper
         * @author Mustafa Zeynel Dağlı
         * @since 0.3 27/01/2016
         * @todo after detail tests code description will be removed
         */
        $this->publicKeyProcessControler($params);
        
        /**
         * public temp key processes wrapper
         * @author Mustafa Zeynel Dağlı
         * @since 0.3 27/01/2016
         * @todo after detail tests code description will be removed
         */
        $this->publicKeyTempProcessControler($params);
        
        
        $preparedParams = $this->prepareGetParams();
        //$preparedParams = $this->prepareGetParams('', array('pk'));
        if (($ch = @curl_init()) == false) {
            header("HTTP/1.1 500", true, 500);
            die("Cannot initialize CURL session. Is CURL enabled for your PHP installation?");
        }
        //print_r($this->restApiFullPathUrl.'?'.$preparedParams);
        curl_setopt($ch, CURLOPT_URL, $this->restApiFullPathUrl . '?' . $preparedParams); //Url together with parameters
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); //Return data instead printing directly in Browser
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->getCallTimeOut()); //Timeout (Default 7 seconds)
        
        /**
         * wrapper for curl header for public key and more
         * @author Mustafa Zeynel Dağlı
         * @since 0.3 27/01/2016
         * @todo after detail tests code description will be removed
         */
        $headerForPublicKeyArr = $this->setCurlHeaderForPublicKey($ch);  
        
        /**
         * wrapper for curl header for public key and more
         * @author Mustafa Zeynel Dağlı
         * @since 0.3 27/01/2016
         * @todo after detail tests code description will be removed
         */
        $headerForPublicKeyTempArr = $this->setCurlHeaderForPublicKeyTemp($ch);
        $curlHeaderArr = array_merge($headerForPublicKeyArr,$headerForPublicKeyTempArr);
        
        
        
        $headerForLogArr = $this->setCurlHeaderForInsertUpdateDelete();
        $curlHeaderArr = array_merge($curlHeaderArr,$headerForLogArr);
        //print_r($headerForLogArr);
        //print_r($curlHeaderArr);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $curlHeaderArr);
        
        /**
         * if request is ssl encrypted consider header options below
         * @author Mustafa Zeynel Dağlı
         * @since 23/12/2015
         */
        /*curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);*/
        curl_setopt($ch, CURLOPT_HEADER, 0); // we don’t want also to get the header information that we receive.
        //sleep(10);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if ($response == false) {
            die("curl_exec() failed. Error: " . curl_error($ch));
        }

        return $response;
    }
    
    /**
     * wrapper function for curl header for insert, update , delete operations log
     * @author Mustafa Zeynel Dağlı
     * @version 0.3 21/03/2016
     * @todo after detailed test curl obj will be removed
     */
    protected function setCurlHeaderForInsertUpdateDelete() {
        
        $logArray = array();
        if($this->isInsertOperationLogged) {
            $logArray[] = 'X-InsertOperationLogged : true';
            //print_r('--isServicePkRequired--');
            /*curl_setopt($chLocal, CURLOPT_HTTPHEADER, array(
                'X-Public: ' . $this->hmacObj->getPublicKey() . '',
                'X-Hash: ' . $this->hmacObj->getHash() . '',
                'X-Nonce:' . $this->hmacObj->getNonce(),
                //'X-IP:'.serialize($_SERVER),
                'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                ->encrypt('' . time() . ''))  /// replay attack lar için oki
            ));*/
        }
        
        if($this->isDeleteOperationLogged) {
            $logArray[] = 'X-DeleteOperationLogged : true';
        }
        
        if($this->isUpdateOperationLogged) {
            $logArray[] = 'X-UpdateOperationLogged : true';
        }
        return $logArray;
    }
    
    /**
     * wrapper function for curl header for public keys and more
     * @author Mustafa Zeynel Dağlı
     * @version 0.3 27/01/2016
     * @todo after detailed test curl obj will be removed
     */
    protected function setCurlHeaderForPublicKey($ch = null) {
        $chLocal = $ch;
        $logArray = array();
        /**
         * if service has to be secure then prepare header for security
         * parameters
         * @author Mustafa Zeynel Dağlı
         * @since version 0.3 06/01/2016
         */
        if($this->isServicePkRequired) {
            //print_r('--isServicePkRequired--');
            $logArray[] = 'X-Public: ' . $this->hmacObj->getPublicKey() . '';
            $logArray[] = 'X-Hash: ' . $this->hmacObj->getHash() . '';
            $logArray[] = 'X-Nonce:' . $this->hmacObj->getNonce();
            $logArray[] = 'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                                         ->encrypt('' . time() . ''));
            /*curl_setopt($chLocal, CURLOPT_HTTPHEADER, array(
                'X-Public: ' . $this->hmacObj->getPublicKey() . '',
                'X-Hash: ' . $this->hmacObj->getHash() . '',
                'X-Nonce:' . $this->hmacObj->getNonce(),
                //'X-IP:'.serialize($_SERVER),
                'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                ->encrypt('' . time() . ''))  /// replay attack lar için oki
            ));*/
        }
        return $logArray;
        //return $chLocal;
    }
    
    /**
     * wrapper function for curl header for public temp keys and more
     * @author Mustafa Zeynel Dağlı
     * @version 0.3 27/01/2016
     */
    protected function setCurlHeaderForPublicKeyTemp($ch = null) {
        $chLocal = $ch;
        $logArray = array();
        /**
         * if service has to be secure then prepare header for security
         * parameters
         * @author Mustafa Zeynel Dağlı
         * @since version 0.3 27/01/2016
         * @todo after detailed test curl obj will be removed
         */
        if($this->isServicePkTempRequired) {
            $logArray[] = 'X-Public-Temp: ' . $this->hmacObj->getPublicKey() . '';
            $logArray[] = 'X-Hash-Temp: ' . $this->hmacObj->getHash() . '';
            $logArray[] = 'X-Nonce:' . $this->hmacObj->getNonce();
            $logArray[] = 'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                                         ->encrypt('' . time() . ''));
            
            /*curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                'X-Public-Temp: ' . $this->hmacObj->getPublicKey() . '',
                'X-Hash-Temp: ' . $this->hmacObj->getHash() . '',
                'X-Nonce:' . $this->hmacObj->getNonce(),
                //'X-IP:'.serialize($_SERVER),
                'X-TimeStamp:' . $this->hmacObj->setTimeStamp($this->encryptClass
                                ->encrypt('' . time() . ''))  /// replay attack lar için oki
            ));*/
        }
        return $logArray;
        //return $chLocal;
    }

    /**
     * public key temp control processes has been wrapped
     * @param array $params
     * @return mixed array | null
     * @throws Exception
     */
    private function publicKeyTempProcessControler($params) {
        if($this->isServicePkTempRequired) {
            /**
            * getting private key temp due to public key temp
            * @author Mustafa Zeynel Dağlı
            * @since 27/01/2016 version 0.3
            */
           if(isset($params['pktemp'])) $resultSetTemp = $this->dalObject->getPrivateKeyTemp($params['pktemp']);
           /**
            * if not get private temp key due to public temp key
            * forward to private not found
            * @author Mustafa Zeynel Dağlı
            * @since 27/01/2016 version 0.3 
            */
           if(empty($resultSetTemp['resultSet'])) $this->privateKeyTempNotFoundRedirect();
           /**
            * if service has to be secure then prepare hash for public and private temp keys
            * @author Mustafa Zeynel Dağlı
            * @since version 0.3 27/01/2016
            */
            if(!isset($resultSetTemp['resultSet'][0]['sf_private_key_value_temp'])){
                throw new \Exception ('SlimHmacProxy->restApiDefaultCall() method private temp key not found!!');
            }
            if(!isset($params['pktemp'])) {
                throw new \Exception ('SlimHmacProxy->restApiDefaultCall() method public temp key not found!!');
            } else {
                $this->hmacObj->setPublicKey($params['pktemp']);
            }

            //$this->hmacObj->setPrivateKey('e249c439ed7697df2a4b045d97d4b9b7e1854c3ff8dd668c779013653913572e');
            $this->hmacObj->setPrivateKey($resultSetTemp['resultSet'][0]['sf_private_key_value_temp']);
            $this->hmacObj->setRequestParams($this->getRequestParamsWithoutPublicKeyTemp());
            $this->hmacObj->makeHmac();
            //print_r($this->hmacObj);
           
           return $resultSetTemp;
        } else {
            return null;
        }
        
    }
    
    /**
     * public key control processes has been wrapped
     * @param array $params
     * @return mixed array | null
     * @throws Exception
     * @author Mustafa Zeynel Dağlı
     * @since 0.3 27/01/2016
     */
    private function publicKeyProcessControler($params) {
        $resultSet;
        if($this->isServicePkRequired) {
            /**
            * getting private key due to public key
            * @author Mustafa Zeynel Dağlı
            * @since 05/01/2016 version 0.3
            */
           if(isset($params['pk'])) $resultSet = $this->dalObject->getPrivateKey($params['pk']);

           /**
            * if not get private key due to public key
            * forward to private not found
            * @author Mustafa Zeynel Dağlı
            * @since 06/01/2016 version 0.3
            */
           if(empty($resultSet['resultSet'])) $this->privateKeyNotFoundRedirect();

           /**
            * if service has to be secure then prepare hash for public and private keys
            * @author Mustafa Zeynel Dağlı
            * @since version 0.3 06/01/2016
            */
            if(!isset($resultSet['resultSet'][0]['sf_private_key_value'])){
                throw new Exception ('SlimHmacProxy->restApiDefaultCall() method private key not found!!');
            }

            if(!isset($params['pk'])) {
                throw new Exception ('SlimHmacProxy->restApiDefaultCall() method public key not found!!');
            } else {
                $this->hmacObj->setPublicKey($params['pk']);
            }

            //$this->hmacObj->setPrivateKey('e249c439ed7697df2a4b045d97d4b9b7e1854c3ff8dd668c779013653913572e');
            $this->hmacObj->setPrivateKey($resultSet['resultSet'][0]['sf_private_key_value']);
            $this->hmacObj->setRequestParams($this->getRequestParamsWithoutPublicKey());
            $this->hmacObj->makeHmac();
            //print_r($this->hmacObj);
           

           return $resultSet;
        } else {
            return null;
        }
        
    }

    public function setEndPointByClosure(Array $EndPointClosure = null) {       
        $endPointFunction = $this->getRestApiEndPointFunction();
        if (substr($endPointFunction, -5) == '_test') {
            //$this->setEndPointUrl("http://localhost/slim2_test/index.php/");
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -15) == '_leftnavigation') {
            $this->setRestApiEndPoint('leftnavigation.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -11) == '_syssectors') {
            $this->setRestApiEndPoint('syssectors.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -10) == '_infoUsers') {
            $this->setRestApiEndPoint('infousers.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -12) == '_syscountrys') {
            $this->setRestApiEndPoint('syscountrys.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }
      /*  else if (substr($endPointFunction, -21) == '_syscountryssilinecek') {
            $this->setRestApiEndPoint('syscountryssilinecek.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }        
       */
          else if (substr($endPointFunction, -8) == '_syscity') {
            $this->setRestApiEndPoint('syscity.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -12) == '_syslanguage') {
            $this->setRestApiEndPoint('syslanguage.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -11) == '_sysborough') {
            $this->setRestApiEndPoint('sysborough.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -11) == '_sysvillage') {
            $this->setRestApiEndPoint('sysvillage.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }
        else if (substr($endPointFunction, -14) == '_blLoginLogout') {
            $this->setRestApiEndPoint('blLoginLogout.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_infoFirmProfile') {
            $this->setRestApiEndPoint('infoFirmProfile.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -12) == '_sysAclRoles') {
            $this->setRestApiEndPoint('sysaclroles.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_sysAclResources') {
            $this->setRestApiEndPoint('sysaclresources.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -16) == '_sysAclPrivilege') {
            $this->setRestApiEndPoint('sysaclprivilege.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -13) == '_sysAclRrpMap') {
            $this->setRestApiEndPoint('sysAclRrpMap.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -23) == '_sysSpecificDefinitions') {
            $this->setRestApiEndPoint('sysspecificdefinitions.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -24) == '_infoUsersCommunications') {
            $this->setRestApiEndPoint('infoUsersCommunications.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -19) == '_infoUsersAddresses') {
            $this->setRestApiEndPoint('infousersaddresses.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -19) == '_blActivationReport') {
            $this->setRestApiEndPoint('blActivationReport.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -18) == '_sysOsbConsultants') {
            $this->setRestApiEndPoint('sysosbconsultants.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -18) == '_sysOperationTypes') {
            $this->setRestApiEndPoint('sysOperationTypes.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -23) == '_sysOperationTypesTools') {
            $this->setRestApiEndPoint('sysoperationtypestools.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -10) == '_infoError') {
            $this->setRestApiEndPoint('infoerror.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -21) == '_sysMachineToolGroups') {
            $this->setRestApiEndPoint('sysmachinetoolgroups.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -16) == '_sysMachineTools') {
            $this->setRestApiEndPoint('sysmachinetools.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -33) == '_sysMachineToolPropertyDefinition') {
            $this->setRestApiEndPoint('sysmachinetoolpropertydefinition.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -25) == '_sysMachineToolProperties') {
            $this->setRestApiEndPoint('sysmachinetoolproperties.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -9) == '_sysUnits') {           
            $this->setRestApiEndPoint('sysunits.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }else if (substr($endPointFunction, -20) == '_infoFirmMachineTool') {
            $this->setRestApiEndPoint('infofirmmachinetool.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -13) == '_sysNaceCodes') {
            $this->setRestApiEndPoint('sysnacecodes.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -11) == '_hstryLogin') {
            $this->setRestApiEndPoint('hstrylogin.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -24) == '_blAdminActivationReport') {
            $this->setRestApiEndPoint('bladminactivationreport.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -14) == '_logConnection') {
            $this->setRestApiEndPoint('logconnection.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -12) == '_logServices') {
            $this->setRestApiEndPoint('logservices.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -14) == '_logConsultant') {
            $this->setRestApiEndPoint('logconsultant.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -9) == '_logAdmin') {
            $this->setRestApiEndPoint('logadmin.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -15) == '_sysUnspscCodes') {
            $this->setRestApiEndPoint('sysunspsccodes.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -18) == '_sysCertifications') {
            $this->setRestApiEndPoint('syscertifications.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -15) == '_sysUnitSystems') {
            $this->setRestApiEndPoint('sysunitsystems.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -19) == '_infoFirmReferences') {
            $this->setRestApiEndPoint('infofirmreferences.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -19) == '_sysProductionTypes') {
            $this->setRestApiEndPoint('sysproductiontypes.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        } else if (substr($endPointFunction, -14) == '_infoFirmUsers') {
            $this->setRestApiEndPoint('infofirmusers.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -34) == '_sysMachineToolDefinitionAttribute') {
            $this->setRestApiEndPoint('sysmachinetooldefinitionattribute.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -21) == '_infoUsersSocialmedia') {
            $this->setRestApiEndPoint('infouserssocialmedia.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -15) == '_infoFirmVerbal') {
            $this->setRestApiEndPoint('infofirmverbal.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -27) == '_infoFirmUserDescForCompany') {
            $this->setRestApiEndPoint('infofirmuserdescforcompany.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -15) == '_sysSocialMedia') {
            $this->setRestApiEndPoint('syssocialmedia.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }  else if (substr($endPointFunction, -20) == '_infoFirmSocialmedia') {
            $this->setRestApiEndPoint('infofirmsocialmedia.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -16) == '_infoFirmAddress') {
            $this->setRestApiEndPoint('infofirmaddress.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -16) == '_sysManufacturer') {
            $this->setRestApiEndPoint('sysmanufacturer.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -17) == '_infoFirmProducts') {
            $this->setRestApiEndPoint('infofirmproducts.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -14) == '_sysMailServer') {
            $this->setRestApiEndPoint('sysmailserver.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -25) == '_infoFirmProductsServices') {
            $this->setRestApiEndPoint('infofirmproductsservices.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -20) == '_infoFirmCertificate') {
            $this->setRestApiEndPoint('infofirmcertificate.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -16) == '_infoFirmQuality') {
            $this->setRestApiEndPoint('infofirmquality.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -17) == '_infoFirmSectoral') {
            $this->setRestApiEndPoint('infofirmsectoral.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }   else if (substr($endPointFunction, -21) == '_infoFirmLanguageInfo') {
            $this->setRestApiEndPoint('infofirmlanguageinfo.php/');
            //    print_r($this->restApiBaseUrl.$this->restApiEndPoint.$this->restApiEndPointFunction);
            $this->setRestApiFullPathUrl($this->restApiBaseUrl . $this->restApiEndPoint . $this->restApiEndPointFunction);
        }                      
        
         
    }

    
    
   
    /**
     * set Hmac object for HMAC security
     * @param \vendor\hmac\Hmac $hmacObj
     * @version 0.2
     * @author Mustafa Zeynel Dağlı
     */
    public function setHmacObj(\vendor\hmac\Hmac $hmacObj) {
        $this->hmacObj = $hmacObj;
    }

    /**
     * get Hmac object for HMAC security
     * @return \vendor\hmac\Hmac $hmacObj
     * @version 0.2
     * @author Mustafa Zeynel Dağlı
     */
    public function getHmacObj() {
        return $this->hmacObj;
    }

}
