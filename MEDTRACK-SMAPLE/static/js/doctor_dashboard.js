document.addEventListener('DOMContentLoaded', async () => {
    try {
        const dashboardData = await fetchData('/api/dashboard');

        // Populate Stats
        document.getElementById('totalPatients').textContent = dashboardData.stats.total_patients || 0;
        document.getElementById('specialization').textContent = dashboardData.stats.specialization || 'N/A';
        document.getElementById('experience').textContent = dashboardData.stats.experience || 0;

        // Populate Upcoming Appointments
        const upcomingAppointmentsList = document.getElementById('upcomingAppointmentsList');
        upcomingAppointmentsList.innerHTML = '';
        if (dashboardData.upcoming_appointments && dashboardData.upcoming_appointments.length > 0) {
            dashboardData.upcoming_appointments.forEach(appt => {
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.innerHTML = `
                    Appointment with ${appt.PatientName} on ${appt.Date} at ${appt.Time} (Status: ${appt.Status})
                    <a href="/doctor/appointments" class="btn btn-sm btn-info float-end ms-2">Manage</a>
                `;
                upcomingAppointmentsList.appendChild(li);
            });
        } else {
            upcomingAppointmentsList.innerHTML = '<li class="list-group-item text-muted">No upcoming appointments.</li>';
        }

        // Populate Notifications
        const notificationsList = document.getElementById('notificationsList');
        notificationsList.innerHTML = '';
        if (dashboardData.notifications && dashboardData.notifications.length > 0) {
            dashboardData.notifications.forEach(notification => {
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.textContent = `${formatDateTime(notification.timestamp)}: ${notification.message}`;
                notificationsList.appendChild(li);
            });
        } else {
            notificationsList.innerHTML = '<li class="list-group-item text-muted">No new notifications.</li>';
        }

        // Populate My Patients (a small list for dashboard, full list on /doctor/patients)
        const myPatientsListDiv = document.getElementById('myPatientsList');
        myPatientsListDiv.innerHTML = '';
        if (dashboardData.patients_under_care && dashboardData.patients_under_care.length > 0) {
            const ul = document.createElement('ul');
            ul.className = 'list-group list-group-flush';
            dashboardData.patients_under_care.slice(0, 5).forEach(patient => { // Show top 5 patients
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.innerHTML = `
                    ${patient.name} (${patient.email})
                    <a href="/doctor/patient/${patient.user_id}/details" class="btn btn-sm btn-primary float-end ms-2">View Details</a>
                `;
                ul.appendChild(li);
            });
            myPatientsListDiv.appendChild(ul);
        } else {
            myPatientsListDiv.innerHTML = '<p class="text-muted">No patients assigned yet.</p>';
        }

    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        alert('Failed to load dashboard data: ' + error.message);
    }
});