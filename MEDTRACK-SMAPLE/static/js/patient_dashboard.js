document.addEventListener('DOMContentLoaded', async () => {
    try {
        const dashboardData = await fetchData('/api/dashboard');
        
        // Populate User Info (already in base.html nav, but for clarity)
        // document.getElementById('userName').textContent = dashboardData.user_info.name;
        // document.getElementById('userRole').textContent = dashboardData.user_info.role;

        // Populate Stats
        document.getElementById('totalActivities').textContent = dashboardData.stats.total_activities || 0;
        document.getElementById('totalCalories').textContent = dashboardData.stats.total_calories_burned || 0;
        document.getElementById('thisWeekActivities').textContent = dashboardData.stats.this_week_activities || 0;
        document.getElementById('activeGoals').textContent = dashboardData.stats.active_goals || 0;

        // Populate Upcoming Appointments
        const upcomingAppointmentsList = document.getElementById('upcomingAppointmentsList');
        upcomingAppointmentsList.innerHTML = '';
        if (dashboardData.upcoming_appointments && dashboardData.upcoming_appointments.length > 0) {
            dashboardData.upcoming_appointments.forEach(appt => {
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.innerHTML = `
                    Appointment with Dr. ${appt.DoctorName} on ${appt.Date} at ${appt.Time} (Status: ${appt.Status})
                    <a href="/patient/appointments" class="btn btn-sm btn-info float-end ms-2">Manage</a>
                `;
                upcomingAppointmentsList.appendChild(li);
            });
        } else {
            upcomingAppointmentsList.innerHTML = '<li class="list-group-item text-muted">No upcoming appointments.</li>';
        }

        // Populate Recent Activities
        const recentActivitiesList = document.getElementById('recentActivitiesList');
        recentActivitiesList.innerHTML = '';
        if (dashboardData.recent_activities && dashboardData.recent_activities.length > 0) {
            dashboardData.recent_activities.forEach(activity => {
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.textContent = `${activity.activity_type} for ${activity.duration} mins on ${activity.date}`;
                recentActivitiesList.appendChild(li);
            });
        } else {
            recentActivitiesList.innerHTML = '<li class="list-group-item text-muted">No recent activities logged.</li>';
        }

        // Populate Recent Health Metrics
        const recentHealthMetricsList = document.getElementById('recentHealthMetricsList');
        recentHealthMetricsList.innerHTML = '';
        if (dashboardData.recent_health_metrics && dashboardData.recent_health_metrics.length > 0) {
            dashboardData.recent_health_metrics.forEach(metric => {
                const li = document.createElement('li');
                li.className = 'list-group-item';
                li.textContent = `${metric.metric_type}: ${metric.value} ${metric.unit} on ${metric.date}`;
                recentHealthMetricsList.appendChild(li);
            });
        } else {
            recentHealthMetricsList.innerHTML = '<li class="list-group-item text-muted">No recent health metrics.</li>';
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

    } catch (error) {
        console.error('Error fetching dashboard data:', error);
        alert('Failed to load dashboard data: ' + error.message);
    }
});