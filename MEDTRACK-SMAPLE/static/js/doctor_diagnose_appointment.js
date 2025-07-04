document.addEventListener('DOMContentLoaded', async () => {
    // APPOINTMENT_ID is passed from Flask template
    if (!APPOINTMENT_ID) {
        alert('Appointment ID not provided.');
        return;
    }

    const appointmentIdDisplay = document.getElementById('appointmentIdDisplay');
    const patientNameDisplay = document.getElementById('patientNameDisplay');
    const appointmentDateDisplay = document.getElementById('appointmentDateDisplay');
    const appointmentTimeDisplay = document.getElementById('appointmentTimeDisplay');
    const diagnosisForm = document.getElementById('diagnosisForm');
    const diagnosisReportInput = document.getElementById('diagnosisReport');
    const diagnosisDateInput = document.getElementById('diagnosisDate');

    async function fetchAppointmentDetails() {
        try {
            // Fetch all doctor's appointments and find the one matching APPOINTMENT_ID
            const allAppointmentsData = await fetchData('/api/appointments');
            const appointment = allAppointmentsData.appointments.find(appt => appt.appointment_id === APPOINTMENT_ID);

            if (appointment) {
                appointmentIdDisplay.textContent = appointment.appointment_id;
                patientNameDisplay.textContent = appointment.PatientName;
                appointmentDateDisplay.textContent = appointment.Date;
                appointmentTimeDisplay.textContent = appointment.Time;
            } else {
                alert('Appointment not found or you are not authorized to diagnose it.');
                window.location.href = '/doctor/appointments'; // Redirect if not found/authorized
            }
        } catch (error) {
            console.error('Error fetching appointment details:', error);
            alert('Failed to load appointment details: ' + error.message);
            window.location.href = '/doctor/appointments';
        }
    }

    diagnosisForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        const report = diagnosisReportInput.value;
        const date = diagnosisDateInput.value;

        try {
            await fetchData(`/api/appointments/${APPOINTMENT_ID}/diagnosis`, 'POST', { report, date });
            alert('Diagnosis submitted successfully!');
            window.location.href = '/doctor/appointments'; // Go back to appointments list
        } catch (error) {
            console.error('Error submitting diagnosis:', error);
            alert('Failed to submit diagnosis: ' + error.message);
        }
    });

    // Set default date for diagnosis to today
    const today = new Date();
    const yyyy = today.getFullYear();
    const mm = String(today.getMonth() + 1).padStart(2, '0'); // Months are 0-indexed
    const dd = String(today.getDate()).padStart(2, '0');
    diagnosisDateInput.value = `${yyyy}-${mm}-${dd}`;

    // Initial load
    fetchAppointmentDetails();
});