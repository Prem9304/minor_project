document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scan-form');
    const loadingSpinner = document.getElementById('scanner-loading');
    const resultsSection = document.getElementById('scan-results');
    const aiContent = document.getElementById('ai-content');
    const rawContent = document.getElementById('raw-content');
    const scanCommand = document.getElementById('scan-command');
    
    let totalScans = 0;
    let activeScans = 0;

    scanForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const ipAddress = document.getElementById('target-ip').value;
        const scanType = document.getElementById('scan-type').value;
        
        // Clear previous results
        aiContent.innerHTML = '';
        rawContent.textContent = '';
        scanCommand.textContent = '';
        
        // Remove any previous error messages
        const previousErrors = resultsSection.querySelectorAll('.alert');
        previousErrors.forEach(error => error.remove());
        
        // Show loading state
        loadingSpinner.style.display = 'block';
        resultsSection.style.display = 'none';
        activeScans++;
        updateDashboard();

        try {
            const response = await fetch('http://192.168.1.9:5000/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    ip: ipAddress,
                    scanType: scanType
                })
            });

            const data = await response.json();
            
            if (data.success) {
                // Display AI Analysis
                if (data.ai_analysis && data.ai_analysis.success) {
                    aiContent.innerHTML = `
                        <div class="alert alert-success">
                            <h5>AI Analysis Results:</h5>
                            ${data.ai_analysis.analysis}
                        </div>
                    `;
                } else {
                    aiContent.innerHTML = `
                        <div class="alert alert-warning">
                            <h5>AI Analysis Warning:</h5>
                            <p>${data.ai_analysis.error || 'AI analysis failed'}</p>
                        </div>
                    `;
                }

                // Display Raw Results
                if (data.command) {
                    scanCommand.textContent = data.command;
                }
                if (data.raw_results) {
                    rawContent.textContent = JSON.stringify(data.raw_results, null, 2);
                }

                // Add to scan history
                addScanToHistory(ipAddress, scanType, 'Completed');
                
                resultsSection.style.display = 'block';
            } else {
                throw new Error(data.error || 'Scan failed');
            }
        } catch (error) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'alert alert-danger';
            errorDiv.innerHTML = `
                <h5>Scan Error:</h5>
                <p>${error.message}</p>
            `;
            resultsSection.insertBefore(errorDiv, resultsSection.firstChild);
            resultsSection.style.display = 'block';
            addScanToHistory(ipAddress, scanType, 'Failed');
        } finally {
            loadingSpinner.style.display = 'none';
            activeScans--;
            totalScans++;
            updateDashboard();
        }
    });

    function addScanToHistory(target, type, status) {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${new Date().toLocaleString()}</td>
            <td>${target}</td>
            <td>${type}</td>
            <td><span class="badge ${status === 'Completed' ? 'bg-success' : 'bg-danger'}">${status}</span></td>
            <td>
                <button class="btn btn-sm btn-primary">View Report</button>
                <button class="btn btn-sm btn-secondary">Download</button>
            </td>
        `;
        const history = document.getElementById('scan-history');
        history.insertBefore(row, history.firstChild);
    }

    function updateDashboard() {
        document.getElementById('total-scans').textContent = totalScans;
        document.getElementById('active-scans').textContent = activeScans;
        document.getElementById('total-reports').textContent = totalScans;
    }
});