from PyQt5 import QtWidgets

# Clears the labels that are used for creating a new plugin to create a new plugin
def deselectPlugin(dpmPluginName_lineEdit, dpmPluginDesc_lineEdit, pluginManagement_list, pluginEditingStatus_label,
                   addPoiXML_label, addPoiManual_label, saveManualPlugin_button, clearManualPlugin_button,
                   poiManagement_list, addPluginXml_frame):

    dpmPluginName_lineEdit.clear()
    dpmPluginDesc_lineEdit.clear()
    pluginManagement_list.clearSelection()
    pluginEditingStatus_label.setStyleSheet("")
    pluginEditingStatus_label.setText('Add Plugin Through Manual Input')
    addPoiXML_label.setStyleSheet("")
    addPoiXML_label.setText('Add POIs Through XML Input')
    addPoiManual_label.setStyleSheet("")
    addPoiManual_label.setText('Add POI Through Manual Input')
    saveManualPlugin_button.setText('Save')
    clearManualPlugin_button.setText('Clear')
    pluginManagement_list.clearSelection()
    poiManagement_list.clear()
    addPluginXml_frame.setDisabled(False)
