Module.ensureInitialized('Foundation');

function getDocumentDir() {
    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = ObjC.classes.NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function getLibraryDir() {
    var NSLibraryDirectory = 5;
    var NSUserDomainMask = 1;
    var npdirs = ObjC.classes.NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function getContainerPath() {
    // Get the app's container path which contains Documents, Library, etc.
    var docDir = getDocumentDir();
    // Remove "/Documents" from the path to get the container path
    return docDir.substring(0, docDir.lastIndexOf('/'));
}

function getBundleIdentifier() {
    return ObjC.classes.NSBundle.mainBundle().bundleIdentifier().toString();
}

function getDataContainers() {
    var result = [];
    
    try {
        // Get the app's bundle identifier
        var bundleId = getBundleIdentifier();
        console.log("[+] Bundle identifier: " + bundleId);
        
        // Get the document directory which contains the data container UUID
        var docDir = getDocumentDir();
        console.log("[+] Document directory: " + docDir);
        
        // Extract the data container UUID from the path
        var match = docDir.match(/\/var\/mobile\/Containers\/Data\/Application\/([^\/]+)/);
        if (match && match[1]) {
            var dataUUID = match[1];
            console.log("[+] Data container UUID: " + dataUUID);
            
            // Add the data container path
            var dataContainerPath = "/var/mobile/Containers/Data/Application/" + dataUUID;
            result.push(dataContainerPath);
        }
        
        // Also get the bundle container path
        var bundlePath = ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        console.log("[+] Bundle path: " + bundlePath);
        
        // Extract the bundle container UUID
        match = bundlePath.match(/\/var\/containers\/Bundle\/Application\/([^\/]+)/);
        if (match && match[1]) {
            var bundleUUID = match[1];
            console.log("[+] Bundle container UUID: " + bundleUUID);
        }
    } catch (e) {
        console.log("[-] Error getting container paths: " + e);
    }
    
    return result;
}

function handleMessage(message) {
    if (message.type === 'error') {
        console.log('Error:', message.description);
        return;
    }
    
    if (message.payload === 'extract') {
        try {
            // Get all relevant container paths
            var containers = getDataContainers();
            
            if (containers.length > 0) {
                console.log("[+] Found " + containers.length + " data containers");
                
                // Send each container path for extraction
                for (var i = 0; i < containers.length; i++) {
                    console.log("[+] Sending container path: " + containers[i]);
                    send({localstorage: containers[i]});
                }
            } else {
                console.log("[-] No data containers found");
                send({localstorage: null});
            }
            
            // Signal that we're done
            send({done: "localstorage_done"});
        } catch (e) {
            console.log("[-] Error extracting local storage: " + e);
            send({localstorage: null});
            send({done: "localstorage_done"});
        }
    }
}

recv(handleMessage);