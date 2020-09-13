const PRIVATE_KEY_STORAGE_NAME = "WebAutoType.VivaldiUrlReceiver.PrivateKey";

let base64Variant = null;
let mostRecentUrlSent = null;
let urlLastSentAt = null;
let libsodiumLoaded = false;
let privateKey = null;

function updateActiveUrl() {
	chrome.windows.getCurrent(currentWindow => {
		chrome.tabs.getAllInWindow(currentWindow.id, tabsInCurrentWindow => {
			const activeTab = tabsInCurrentWindow.find(tab => tab.active);
			if(!activeTab) return;

			const activeTabUrl = activeTab.url;
			const now = new Date();

			if(activeTabUrl !== "" && (activeTabUrl !== mostRecentUrlSent || mostRecentUrlSent === null || now - urlLastSentAt >= 500)) {
				mostRecentUrlSent = activeTabUrl;
				urlLastSentAt = now;
				sendActiveUrlUsingXhr(activeTabUrl);
			}
		});
	});
}

async function sendActiveUrlUsingXhr(currentUrl){
	const request = new XMLHttpRequest();

	let encrypted;
	try {
		encrypted = await encryptUrl(currentUrl);
	} catch(e){
		console.warn("Failed to encrypt current URL, so not sending anything to KeePass.", e);
		return;
	}

	const requestBody = new URLSearchParams();
	requestBody.set("activeUrlEncrypted", sodium.to_base64(encrypted.ciphertext, base64Variant));
	requestBody.set("nonce", sodium.to_base64(encrypted.nonce, base64Variant));

	request.open("POST", "http://127.0.0.1:53372/webautotype/activeurl/vivaldi");
	request.send(requestBody);
	console.info("Sent active URL ("+currentUrl+") to KeePass.");
}

async function encryptUrl(url, callback) {
	if(!libsodiumLoaded){
		throw new Error("libsodium has not loaded yet");
	} else if(privateKey == null){
		await loadPrivateKey();
	}

	const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
	const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(url, null, null, nonce, privateKey);

	return { ciphertext, nonce };
}

function loadPrivateKey(){
	return new Promise((resolve, reject) => {
		chrome.storage.local.get([PRIVATE_KEY_STORAGE_NAME], function(result){
			var privateKeyBase64 = result[PRIVATE_KEY_STORAGE_NAME];
			if(privateKeyBase64){
				privateKey = sodium.from_base64(privateKeyBase64, base64Variant);
				resolve();
			} else {
				reject(new Error("No private key in local storage."));
			}
		});
	});
}

['onCreated', 'onRemoved', 'onFocusChanged'].forEach(windowEventName => {
	chrome.windows[windowEventName].addListener(updateActiveUrl);
});

['onCreated', 'onUpdated', 'onActivated', 'onDetached', 'onAttached', 'onRemoved', 'onReplaced'].forEach(tabEventName => {
	chrome.tabs[tabEventName].addListener(updateActiveUrl);
});

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
	if(sender.id !== "mpognobbkildjkofajifpdfhcoklimli") return; //Only allow from Vivaldi's browser.html
	
	if(request.windowActivated){
		updateActiveUrl();
		sendResponse(true);
	}
});

// libsodium.js seems to not work with native browser ES6 module importing
window.sodium = {
	onload: async function(){
		console.info("Sodium loaded.");
		libsodiumLoaded = true;
		base64Variant = sodium.base64_variants.URLSAFE_NO_PADDING;

		try {
			await loadPrivateKey();
			updateActiveUrl();
		} catch(e) {
			console.error(e);
		}
	}
};

console.log("Waiting for Sodium to load...");