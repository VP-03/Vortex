// charts.js
let currentSelectedRange = '24h';
document.addEventListener('DOMContentLoaded', function () {
    AOS.init(); // Initialize AOS animations
    console.log("DOM Content Loaded");
    
    fetchAttackData();
    initializeTimeRangeSelectors();
    initializeMapButton();
});

// Global chart variables
let timelineChart = null;
let attackTypesChart = null;
let countryChart = null;

const attackTypeColors = [
    '#af3dff', '#55ffe1', '#ff3b94', '#a6fd29',
    '#37013a', '#ffe28a', '#6fcb9f', '#f8d1a0', '#fb2e01',
];
const attackTypeColorMap = {};
let nextColorIndex = 0;

// Assign a consistent color to each attack type
function getAttackTypeColor(type) {
    if (!attackTypeColorMap[type]) {
        attackTypeColorMap[type] = attackTypeColors[nextColorIndex % attackTypeColors.length];
        nextColorIndex++;
    }
    return attackTypeColorMap[type];
}

// Initialize time range selector buttons
function initializeTimeRangeSelectors() {
    const timeButtons = document.querySelectorAll('.time-btn');
    timeButtons.forEach(button => {
        button.addEventListener('click', function() {
            timeButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            const range = this.getAttribute('data-range');
            console.log(`Time range changed to: ${range}`);
            fetchAttackData(range);
        });
    });
}

// Initialize Map Button
function initializeMapButton() {
    const mapButton = document.getElementById('show-on-map');
    if (mapButton) {
        mapButton.addEventListener('click', function() {
            if (attackTypesChart && attackTypesChart.getActiveElements) {
                const selectedTypes = attackTypesChart.getActiveElements().map(e => 
                    attackTypesChart.data.labels[e.index]);
                if (selectedTypes.length > 0) {
                    window.location.href = `/map?types=${encodeURIComponent(selectedTypes.join(','))}`;
                } else {
                    window.location.href = '/map';
                }
            } else {
                window.location.href = '/map';
            }
        });
    }
}

// Fetch data from the server
function fetchAttackData(timeRange = '24h') {
    currentSelectedRange = timeRange;
    console.log("Fetching attack data...");
    fetch('/api/attack-data')
        .then(response => response.json())
        .then(data => {
            console.log("Received data:", data);
            if (!data || !data.length) {
                document.getElementById('no-data-alert').style.display = 'block';
                document.getElementById('loadingOverlay').style.display = 'none';
                return;
            }
            const filteredData = filterDataByTimeRange(data, timeRange);
            processAttackData(filteredData);
            document.getElementById('loadingOverlay').style.display = 'none';
        })
        .catch(error => {
            console.error('Error fetching attack data:', error);
            document.getElementById('error-alert').style.display = 'block';
            document.getElementById('loadingOverlay').style.display = 'none';
        });
}

// Filter data by selected time range
function filterDataByTimeRange(data, timeRange) {
    if (!data || !data.length) return [];

    const now = new Date();
    let cutoffDate = new Date();

    switch(timeRange) {
        case '12h': cutoffDate.setHours(now.getHours() - 12); break;
        case '24h': cutoffDate.setHours(now.getHours() - 24); break;
        case '7d': cutoffDate.setDate(now.getDate() - 7); break;
        case '30d': cutoffDate.setDate(now.getDate() - 30); break;
        case '90d': cutoffDate.setDate(now.getDate() - 90); break;
        default: cutoffDate.setHours(now.getHours() - 24);
    }

    return data.filter(attack => {
        const attackDate = new Date(attack.timestamp);
        return attackDate >= cutoffDate;
    });
}

// Process and plot the data
function processAttackData(data) {
    console.log("Processing attack data:", data);

    const timelineData = {};
    const attackTypes = {};
    const countryData = {};
    const severityData = { 'High': 0, 'Medium': 0, 'Low': 0 };
    const uniqueIPs = new Set();
    const uniqueCategories = new Set();
    let totalHits = 0;

    data.forEach(attack => {
        const dateObj = new Date(attack.timestamp);
        let date;
        if (['7d', '30d', '90d'].includes(currentSelectedRange)) {
            date = `${dateObj.getFullYear()}-${(dateObj.getMonth()+1).toString().padStart(2,'0')}-${dateObj.getDate().toString().padStart(2,'0')}`;
        } else {
            date = `${dateObj.getFullYear()}-${(dateObj.getMonth()+1).toString().padStart(2,'0')}-${dateObj.getDate().toString().padStart(2,'0')} ${dateObj.getHours().toString().padStart(2,'0')}:00`;
        }
        const type = attack.attack_type || 'Other';
        const hits = attack.hits || 1;

        if (!timelineData[type]) timelineData[type] = {};
        timelineData[type][date] = (timelineData[type][date] || 0) + hits;

        attackTypes[type] = (attackTypes[type] || 0) + hits;

        const country = attack.country || 'Unknown';
        countryData[country] = (countryData[country] || 0) + hits;

        if (attack.severity) {
            let severityText = 'Low';
            if (attack.severity >= 3) severityText = 'High';
            else if (attack.severity == 2) severityText = 'Medium';
            severityData[severityText] += hits;
        }

        if (attack.category) uniqueCategories.add(attack.category);
        if (attack.ip) uniqueIPs.add(attack.ip);

        totalHits += hits;
    });

    updateStats(uniqueIPs.size, Object.keys(attackTypes).length, totalHits, data.length, uniqueCategories.size);

    plotTimelineChart(timelineData);
    plotAttackTypesChart(attackTypes);
    plotCountryChart(countryData);
    populateTopAttackers(data);
}

// Update the stat cards
function updateStats(uniqueIPCount, attackTypeCount, totalHits, totalAttacks, categoryCount) {
    document.getElementById('total-attacks').innerText = totalAttacks;
    document.getElementById('unique-ips').innerText = uniqueIPCount;
    document.getElementById('attack-types').innerText = attackTypeCount;
    document.getElementById('total-hits').innerText = totalHits;
}

function getStepSizeForTimeline() {
    switch (currentSelectedRange) {
        case '12h':
            return 1; // 1 hour steps
        case '24h':
            return 1; // 1 hour steps
        case '7d':
            return 6; // 6 hour steps
        case '30d':
            return 24; // 1 day steps
        case '90d':
            return 48; // 2 day steps
        default:
            return 1; // Fallback
    }
}

// Plot the Attack Timeline Chart
function plotTimelineChart(timelineData) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    if (timelineChart instanceof Chart) timelineChart.destroy();

    const now = new Date();
    let startDate = new Date();
    switch (currentSelectedRange) {
        case '12h': startDate.setHours(now.getHours() - 12); break;
        case '24h': startDate.setHours(now.getHours() - 24); break;
        case '7d': startDate.setDate(now.getDate() - 7); break;
        case '30d': startDate.setDate(now.getDate() - 30); break;
        case '90d': startDate.setDate(now.getDate() - 90); break;
        default: startDate.setHours(now.getHours() - 24);
    }

    const endDate = now;
    const unit = ['7d', '30d', '90d'].includes(currentSelectedRange) ? 'day' : 'hour';
    const sortedDates = generateTimeline(startDate, endDate, unit);

    // Log the sorted dates to verify
    console.log("Sorted Dates:", sortedDates);

    const datasets = [];
    Object.keys(timelineData).forEach(type => {
        const dataPoints = sortedDates.map(date => {
            const dataPoint = timelineData[type][date] || 0;
            return dataPoint;
        });

        // Log the data for each attack type
        console.log(`Data for ${type}:`, timelineData[type]);

        const color = getAttackTypeColor(type);

        datasets.push({
            label: type,
            data: dataPoints,
            borderColor: color,
            backgroundColor: color,
            fill: false,
            tension: 0.4,
            pointRadius: 4,
            pointHoverRadius: 8,
            pointBorderWidth: 2,
            pointHoverBorderWidth: 4,
            pointBorderColor: color,
            pointHoverBorderColor: '#ffffff',
            pointHoverBackgroundColor: color,
        });
    });

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: { labels: sortedDates, datasets: datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'nearest', intersect: true },
            plugins: {
                legend: { position: 'top', labels: { color: '#ffffff' } },
                tooltip: {
                    mode: 'nearest',
                    intersect: true,
                    backgroundColor: 'rgba(18, 19, 22, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#a0a0a0',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: true,
                    callbacks: {
                        title: function(tooltipItems) {
                            const date = new Date(tooltipItems[0].label);
                            return date.toLocaleString('en-IN', {
                                weekday: 'long', year: 'numeric', month: 'short',
                                day: 'numeric', hour: unit === 'hour' ? 'numeric' : undefined,
                                minute: unit === 'hour' ? '2-digit' : undefined
                            });
                        },
                        label: function(context) {
                            const attackType = context.dataset.label || 'Unknown Attack';
                            const hits = context.raw || 0;
                            return `${attackType}: ${hits} hits`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: unit,
                        tooltipFormat: unit === 'day' ? 'MMM d, yyyy' : 'MMM d, ha',
                        displayFormats: unit === 'day' ? { day: 'MMM d' } : { hour: 'MMM d, ha' }
                    },
                    ticks: {
                        color: '#ffffff',
                        autoSkip: false,
                        maxRotation: 45,
                        minRotation: 45
                    },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: '#ffffff', precision: 0 },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                }
            },
            animations: {
                tension: { duration: 1000, easing: 'linear' }
            }
        }
    });
}

function generateTimeline(startDate, endDate, unit = 'hour') {
    const timeline = [];
    let current = new Date(startDate);

    while (current <= endDate) {
        let timestamp;
        if (unit === 'day') {
            timestamp = `${current.getFullYear()}-${(current.getMonth()+1).toString().padStart(2,'0')}-${current.getDate().toString().padStart(2,'0')}`;
            current.setDate(current.getDate() + 1);
        } else {
            timestamp = `${current.getFullYear()}-${(current.getMonth()+1).toString().padStart(2,'0')}-${current.getDate().toString().padStart(2,'0')} ${current.getHours().toString().padStart(2,'0')}:00`;
            current.setHours(current.getHours() + 1);
        }
        timeline.push(timestamp);
    }
    return timeline;
}
// Plot Attack Types Chart
function plotAttackTypesChart(attackTypes) {
    const ctx = document.getElementById('attack-types-chart').getContext('2d');
    if (attackTypesChart instanceof Chart) attackTypesChart.destroy();

    const attackTypeLabels = Object.keys(attackTypes);
    const colors = attackTypeLabels.map(type => getAttackTypeColor(type));

    attackTypesChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: attackTypeLabels,
            datasets: [{
                label: 'Attack Types',
                data: Object.values(attackTypes),
                backgroundColor: colors,
                borderColor: '#0a0b0e',
                borderWidth: 2,
                hoverOffset: 15
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#ffffff', padding: 15 } },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} hits (${percentage}%)`;
                        }
                    }
                }
            },
            cutout: '60%'
        }
    });
}

// Plot Country-wise Chart
function plotCountryChart(countryData) {
    const ctx = document.getElementById('country-chart').getContext('2d');
    if (countryChart instanceof Chart) countryChart.destroy();

    const sortedCountries = Object.entries(countryData).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const labels = sortedCountries.map(item => item[0]);
    const values = sortedCountries.map(item => item[1]);

    const gradientColors = labels.map((_, index) => {
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);
        const hue = (200 + index * 30) % 360;
        gradient.addColorStop(0, `hsla(${hue}, 100%, 60%, 0.8)`);
        gradient.addColorStop(1, `hsla(${hue}, 100%, 40%, 0.6)`);
        return gradient;
    });

    countryChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Hits',
                data: values,
                backgroundColor: gradientColors,
                borderColor: 'rgba(0, 102, 255, 0.8)',
                borderWidth: 1,
                borderRadius: 4,
                barThickness: 'flex',
                maxBarThickness: 30
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(18, 19, 22, 0.8)',
                    titleColor: '#ffffff',
                    bodyColor: '#a0a0a0',
                    borderColor: 'rgba(255, 255, 255, 0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false,
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.raw} hits`;
                        }
                    }
                }
            },
            scales: {
                x: {
                    ticks: { color: '#ffffff', autoSkip: false, maxRotation: 45, minRotation: 45 },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: { color: '#ffffff', precision: 0 },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                }
            }
        }
    });
}

// Populate Top Attackers Table
function populateTopAttackers(attackers) {
    const tableBody = document.getElementById('attacker-table-body');
    tableBody.innerHTML = '';

    attackers.sort((a, b) => (b.hits || 0) - (a.hits || 0));
    const topAttackers = attackers.slice(0, 10);

    topAttackers.forEach(attacker => {
        const row = document.createElement('tr');
        let severityClass = 'badge-severity-low';
        if (attacker.severity >= 3) severityClass = 'badge-severity-high';
        else if (attacker.severity == 2) severityClass = 'badge-severity-medium';

        row.innerHTML = `
            <td><span class="d-inline-block text-truncate" style="max-width: 150px;" title="${attacker.ip}">${attacker.ip}</span></td>
            <td>${attacker.country || 'Unknown'}</td>
            <td>${attacker.city || 'Unknown'}</td>
            <td><span class="badge ${severityClass}">${attacker.hits || 0}</span></td>
            <td><span class="d-inline-block text-truncate" style="max-width: 150px;" title="${attacker.attack_type}">${attacker.attack_type}</span></td>
            <td>${new Date(attacker.last_seen || attacker.timestamp).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}</td>
        `;
        tableBody.appendChild(row);
    });
}