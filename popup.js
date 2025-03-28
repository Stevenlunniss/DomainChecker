document.addEventListener('DOMContentLoaded', () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        const errorMsgEl = document.getElementById('error-message');
        const domainNameEl = document.getElementById('domain-name');

        function showGeneralError(message) {
            if (errorMsgEl) {
                errorMsgEl.textContent = message;
                errorMsgEl.style.display = 'block';
            }
            // Hide check sections
            document.querySelectorAll('.record-section').forEach(el => el.style.display = 'none');
             if (domainNameEl) domainNameEl.textContent = "Error";
        }

        if (chrome.runtime.lastError) {
            showGeneralError(`Error getting tab: ${chrome.runtime.lastError.message}`);
            return;
        }

        if (!tabs || tabs.length === 0 || !tabs[0]?.url) {
            showGeneralError('Cannot access current tab URL.');
            return;
        }

        let url;
        try {
            url = new URL(tabs[0].url);
        } catch (e) {
            showGeneralError(`Invalid URL: ${tabs[0].url}`);
            return;
        }

        if (!url.hostname) {
             showGeneralError('Cannot extract domain from URL.');
             return;
        }
        // Only proceed for http/https protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            showGeneralError(`Cannot perform checks on '${url.protocol}' pages.`);
             if (domainNameEl) domainNameEl.textContent = `Domain: ${url.hostname} (${url.protocol})`;
             // Hide check sections but show domain info
             document.querySelectorAll('.record-section').forEach(el => el.style.display = 'none');
            return;
        }

        const domain = url.hostname;
        if (domainNameEl) domainNameEl.textContent = `Domain: ${domain}`;

        // --- Start Checks ---
        checkSpf(domain);
        checkDmarc(domain);
        checkDkim(domain);
    });
});

// --- Helper to update UI ---
function updateStatus(sectionId, status, data = '') {
    const statusEl = document.getElementById(`${sectionId}-status`);
    const recordEl = document.getElementById(`${sectionId}-record`);
    const dkimInfoEl = document.getElementById('dkim-info'); // Specific for DKIM note

    if (!statusEl) {
        console.warn(`UI status element not found for section: ${sectionId}`);
        return; // Don't try to update if element doesn't exist
    }
     if (!recordEl && status !== 'error' && status !== 'loading') {
         console.warn(`UI record element not found for section: ${sectionId}`);
          // Don't absolutely need recordEl for error/loading status, but log it.
     }


    let statusText = '';
    let statusClass = ''; // For CSS styling

    switch (status) {
        case 'loading': statusText = '⏳ Checking...'; statusClass = 'loading'; break;
        case 'found': statusText = '✅ Found'; statusClass = 'success'; break;
        case 'not-found': statusText = '❌ Not Found'; statusClass = 'not-found'; break;
        case 'error': statusText = `⚠️ Error: ${data}`; statusClass = 'error'; data = ''; break; // Show error msg in status span
        default: statusText = status; // Allow custom text
    }

    statusEl.textContent = statusText;
    statusEl.className = `status ${statusClass}`; // Apply CSS class

    if (recordEl) {
        // Use textContent for safety; remove potential surrounding quotes from DNS data
        const cleanedData = typeof data === 'string' ? data.trim().replace(/^"|"$/g, '') : data;
        recordEl.textContent = cleanedData;
        // Show/hide the <pre> block based on whether there's data and it's not an error status
        recordEl.style.display = (cleanedData && status !== 'error' && status !== 'loading' && status !== 'not-found') ? 'block' : 'none';
    }
    // Show DKIM note only after DKIM check is done (found or not-found)
    if (sectionId === 'dkim' && dkimInfoEl && (status === 'found' || status === 'not-found')) {
        dkimInfoEl.style.display = 'block';
    }
     if (sectionId === 'dkim' && dkimInfoEl && (status === 'loading' || status === 'error')) {
         dkimInfoEl.style.display = 'none';
     }
}


// --- DNS Lookup using Google DoH ---
async function lookupDnsRecord(name, type) {
    // See https://developers.google.com/speed/public-dns/docs/doh/json
    const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
    console.log(`Querying DoH: ${url}`); // For debugging
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/dns-json'
            },
             credentials: 'omit' // Explicitly omit credentials
        });
        if (!response.ok) {
            // Try to get more specific error from response if possible
             let errorBody = '';
             try { errorBody = await response.text(); } catch(e) {} // Ignore if body can't be read
            throw new Error(`HTTP error ${response.status}${errorBody ? ': ' + errorBody : ''}`);
        }
        const data = await response.json();
        console.log(`DoH Response for ${name} (${type}):`, data); // For debugging

        // Google DoH Status: 0 = NOERROR (Success, record may or may not exist)
        // 2 = SERVFAIL, 3 = NXDOMAIN (Domain doesn't exist)
        if (data.Status === 3) { // NXDOMAIN
             return { records: [] }; // Domain doesn't exist, so no records
        }
         if (data.Status !== 0) {
             // Other DNS error
              console.warn(`DoH query failed for ${name} (${type}) with Status: ${data.Status}`);
             return { error: `DNS query failed (Status: ${data.Status})` };
         }

        // Success (Status 0), check if 'Answer' array exists and has records
        if (!data.Answer || data.Answer.length === 0) {
            return { records: [] }; // NOERROR, but no records of the requested type found
        }

        // Filter by requested type again, as DoH might return CNAMEs along with TXT etc.
        const relevantAnswers = data.Answer.filter(ans => ans.type === (type === 'TXT' ? 16 : (type === 'CNAME' ? 5 : 1))); // 16=TXT, 5=CNAME, 1=A
        return { records: relevantAnswers.map(ans => ans.data) }; // Extract the record data string

    } catch (error) {
        console.error(`Workspace/Network error for ${name} (${type}):`, error);
        return { error: error.message || 'Network request failed' };
    }
}

// --- Specific Check Functions ---
async function checkSpf(domain) {
    updateStatus('spf', 'loading');
    const result = await lookupDnsRecord(domain, 'TXT');

    if (result.error) {
        updateStatus('spf', 'error', result.error);
        return;
    }

    // Find TXT record starting with v=spf1 (case-insensitive check recommended for 'v=spf1')
    const spfRecord = result.records.find(txt =>
        typeof txt === 'string' && txt.trim().replace(/^"|"$/g, '').toLowerCase().startsWith('v=spf1')
    );

    if (spfRecord) {
        updateStatus('spf', 'found', spfRecord); // Pass raw record data from result
    } else {
        updateStatus('spf', 'not-found');
    }
}

async function checkDmarc(domain) {
    updateStatus('dmarc', 'loading');
    const dmarcDomain = `_dmarc.${domain}`;
    const result = await lookupDnsRecord(dmarcDomain, 'TXT');

     if (result.error) {
        updateStatus('dmarc', 'error', result.error);
        return;
    }
    // Find TXT record starting with v=DMARC1 (case-insensitive recommended)
    const dmarcRecord = result.records.find(txt =>
         typeof txt === 'string' && txt.trim().replace(/^"|"$/g, '').toLowerCase().startsWith('v=dmarc1')
    );

    if (dmarcRecord) {
        updateStatus('dmarc', 'found', dmarcRecord);
    } else {
        updateStatus('dmarc', 'not-found');
    }
}

async function checkDkim(domain) {
    updateStatus('dkim', 'loading');
    // Common selectors list - expand as needed
    const commonSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mandrill', 's1', 's2'];
    let foundRecords = [];
    let queryErrors = []; // Track errors for individual selectors

    for (const selector of commonSelectors) {
        const dkimDomain = `${selector}._domainkey.${domain}`;
        const result = await lookupDnsRecord(dkimDomain, 'TXT');

        if (result.error) {
            // Don't treat individual selector errors as fatal, just note them
            // Avoid flooding the UI, maybe just log? Or add to a summary.
             // queryErrors.push(`${selector}: ${result.error}`); // Option to collect errors
             console.log(`Note: Error checking DKIM selector '${selector}': ${result.error}`);
             continue; // Skip to next selector
        }

        if (result.records && result.records.length > 0) {
             // Find TXT record starting with v=DKIM1 (case-insensitive recommended)
             const dkimRecord = result.records.find(txt =>
                 typeof txt === 'string' && txt.trim().replace(/^"|"$/g, '').toLowerCase().startsWith('v=dkim1')
             );
            if(dkimRecord) {
                // Add selector info to the displayed record for clarity
                foundRecords.push(`Selector '${selector}':\n${dkimRecord}`);
            }
            // Optional: You could also check/report CNAMEs here if desired
        }
    }

    if (foundRecords.length > 0) {
        // Join multiple found records with newlines for the <pre> tag
        updateStatus('dkim', 'found', foundRecords.join('\n\n'));
    } else {
         // Add error summary if any selectors failed?
         // let notFoundMessage = `No DKIM 'v=DKIM1' records found for selectors checked: ${commonSelectors.join(', ')}.`;
         // if (queryErrors.length > 0) {
         //     notFoundMessage += `\n(Note: Some selector lookups failed)`;
         // }
         updateStatus('dkim', 'not-found', `No DKIM 'v=DKIM1' records found for selectors checked.`);
    }
}
