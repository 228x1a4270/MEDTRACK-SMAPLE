document.addEventListener('DOMContentLoaded', async () => {
    // PATIENT_USER_ID is passed from Flask template
    if (!PATIENT_USER_ID) {
        console.error('Patient ID not provided.'); // Use console.error for dev visibility
        alert('Patient ID not provided. Redirecting...');
        window.location.href = '/doctor/patients'; // Redirect if no patient ID
        return;
    }

    // ... (other variable declarations)

    const patientDiagnosesList = document.getElementById('patientDiagnosesList');

    // --- ADD THIS CHECK HERE ---
    if (!patientDiagnosesList) {
        console.error('Error: patientDiagnosesList element not found in the DOM.');
        return; // Stop execution
    }
    // ----------------------------

    // ... (other functions)

    async function fetchPatientDiagnoses() {
        patientDiagnosesList.innerHTML = '<p class="text-muted">Loading diagnoses...</p>';
        try {
            const data = await fetchData(`/api/diagnosis/patient/${PATIENT_USER_ID}`);
            patientDiagnosesList.innerHTML = ''; // Clear previous content
            if (data.diagnoses.length === 0) {
                patientDiagnosesList.innerHTML = '<p class="text-muted">No diagnoses found for this patient.</p>';
            } else {
                const ul = document.createElement('ul');
                ul.className = 'list-group';
                data.diagnoses.forEach(diag => {
                    const li = document.createElement('li');
                    li.className = 'list-group-item mb-2';
                    li.innerHTML = `
                        <h6>Diagnosis from Dr. ${diag.DoctorName} on ${diag.Date}</h6>
                        <p>${diag.Report.substring(0, 150)}...</p>
                        <a href="#" class="btn btn-sm btn-info view-diagnosis-btn" data-diagnosis-id="${diag.diagnosis_id}">View Full Report</a>
                    `;
                    ul.appendChild(li);
                });
                patientDiagnosesList.appendChild(ul);

                // Add event listener for view full report buttons (if you implement a modal for full view)
                document.querySelectorAll('.view-diagnosis-btn').forEach(button => {
                    button.addEventListener('click', async (event) => {
                        event.preventDefault();
                        const diagnosisId = event.target.dataset.diagnosisId;
                        try {
                            const diagData = await fetchData(`/api/diagnosis/${diagnosisId}`);
                            alert(`Full Diagnosis Report from Dr. ${diagData.diagnosis.DoctorName} on ${diagData.diagnosis.Date}:\n\n${diagData.diagnosis.Report}`);
                        } catch (err) {
                            alert('Failed to load full diagnosis: ' + err.message);
                        }
                    });
                });
            }
        } catch (error) {
            console.error('Error fetching patient diagnoses:', error);
            patientDiagnosesList.innerHTML = `<p class="text-danger">Failed to load diagnoses: ${error.message}</p>`;
        }
    }

    // ... (rest of the file)
});