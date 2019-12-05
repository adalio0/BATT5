
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

def displayPlugin(name, description, pluginManagement_list, addPoiType_dropdown, pluginEditingStatus_label, addPoiXML_label,
          addPoiManual_label, dpmPluginName_lineEdit, dpmPluginDesc_lineEdit, saveManualPlugin_button,
          clearManualPlugin_button, addPluginXml_frame):

    if pluginManagement_list.selectedItems():
        # get name of current plugin
        item = pluginManagement_list.currentItem().text()
        poi = addPoiType_dropdown.currentText()
        # set label to display name of plugin being edited
        pluginEditingStatus_label.setStyleSheet("font-weight: bold")
        pluginEditingStatus_label.setText('Currently Editing: {}'.format(item))

        addPoiXML_label.setStyleSheet("font-weight: bold")
        addPoiXML_label.setText('Add POIs to {}'.format(item) + ' Through XML Input')
        addPoiXML_label.setText('Add POIs to {}'.format(item) + ' Through XML Input')

        addPoiManual_label.setStyleSheet("font-weight: bold")
        addPoiManual_label.setText(
            'Add {}'.format(poi) + ' to {}'.format(item) + ' Through Manual Input')
        # display poi information
        dpmPluginName_lineEdit.setText(name)
        dpmPluginDesc_lineEdit.setText(description)

        saveManualPlugin_button.setText('Update Plugin')
        clearManualPlugin_button.setText('De-Select Plugin')
        # self.displayPoiFromPlugin()
        addPluginXml_frame.setDisabled(True)
