const JiraUtils = {
    getLensDesktopVersion: () => Array.from(document.querySelectorAll("[data-id='environment'] .table__row"))
        .find(r => r.children[0].textContent.trim() === 'lens-desktop-version')?.children[1].textContent.trim(),
    
    parseUrl: () => {
        const url = window.location.href;
        const projectMatch = url.match(/\/projects\/([^\/]+)\/reports/);
        const buildMatch = url.match(/\/reports\/([^\/]+)\/index\.html/);
        return {
            projectId: projectMatch?.[1] || null,
            buildId: buildMatch?.[1] || null
        };
    },
    
    buildApiUrl: (projectId, buildId, endpoint = 'jira', index = '') => 
        `http://localhost:5050/allure-docker-service/api/${endpoint}/${projectId}/${buildId}${index ? '/' + index : ''}`,
    
    addLensVersion: (url) => {
        const version = JiraUtils.getLensDesktopVersion();
        return version ? `${url}?lensDesktopVersion=${encodeURIComponent(version)}` : url;
    },
    
    apiCall: async (url, options = {}) => {
        url = JiraUtils.addLensVersion(url);
        return fetch(url, options);
    },

    extractTicketNumber: (ticketInput) => {
        const patterns = [
            /\/([A-Z]+-\d+)(?:\/|$)/, 
            /browse\/([A-Z]+-\d+)/,    
            /ticket\/([A-Z]+-\d+)/,   
            /issue\/([A-Z]+-\d+)/,     
            /^([A-Z]+-\d+)$/          
        ];
        
        for (const pattern of patterns) {
            const match = ticketInput.match(pattern);
            if (match) return match[1];
        }
        
        return ticketInput;
    }
};

class JiraTicketsWidget {
    constructor() {
        this.projectId = null;
        this.buildId = null;
        this.init();
    }

    init() {
        const ids = JiraUtils.parseUrl();
        this.projectId = ids.projectId;
        this.buildId = ids.buildId;
        
        if (this.buildId === 'latest' && this.projectId) {
            this.getActualReportId();
        }
    }

    async getActualReportId() {
        try {
            const response = await fetch(`http://localhost:5050/projects/${this.projectId}`);
            const data = await response.json();
            if (data.data?.project?.reports_id?.length > 1) {
                this.buildId = data.data.project.reports_id[1];
            }
        } catch (error) {
            console.error('[JIRA-TICKETS] Error fetching project data:', error);
        }
    }

    createTemplate() {
        return `
            <div>
                <h2 style="margin-top: 0; font-weight: normal;">JIRA TICKETS</h2>
                <div class="data-section">
                    <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                        <input type="text" id="ticket-input" placeholder="Add JIRA ticket URL..." 
                               style="flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; outline: none; font-family: inherit; height: 36px;" />
                        <button id="save-ticket-btn" 
                                style="padding: 8px 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px;">
                            Add
                        </button>
                    </div>
                    <div id="tickets-list" style="min-height: 0; margin-bottom: 20px;"></div>
                </div>
            </div>
        `;
    }

    setupEventHandlers() {
        const saveBtn = document.getElementById('save-ticket-btn');
        const ticketInput = document.getElementById('ticket-input');
        
        if (!saveBtn || !ticketInput) return;

        const saveTicket = () => this.saveTicket(ticketInput.value.trim());
        saveBtn.onclick = saveTicket;
        ticketInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') saveTicket();
        });
    }

    async saveTicket(ticketText) {
        if (!ticketText) return alert('Please enter a JIRA ticket');
        if (!this.projectId || !this.buildId) return alert('Unable to determine project/build from URL');

        const ticketNumber = JiraUtils.extractTicketNumber(ticketText);

        try {
            const url = JiraUtils.buildApiUrl(this.projectId, this.buildId);
            const response = await JiraUtils.apiCall(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ticket_id: ticketNumber })
            });
            
            const data = await response.json();
            if (data.message) {
                alert('Ticket saved!');
                document.getElementById('ticket-input').value = '';
                this.loadTickets();
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error: ' + error.message);
        }
    }

    async loadTickets() {
        const ticketsList = document.getElementById('tickets-list');
        if (!ticketsList || !this.projectId || !this.buildId) return;

        try {
            const url = JiraUtils.buildApiUrl(this.projectId, this.buildId);
            const response = await JiraUtils.apiCall(url);
            
            if (response.status === 404) {
                ticketsList.innerHTML = '';
                return;
            }

            const data = await response.json();
            if (!data || Object.keys(data).length === 0) {
                ticketsList.innerHTML = '';
                return;
            }

            const tickets = Object.keys(data).map(key => ({
                ticket_id: data[key].ticket_id || data[key],
                index: key
            })).sort((a, b) => parseInt(b.index) - parseInt(a.index));

            this.displayTickets(tickets);
        } catch (error) {
            ticketsList.innerHTML = `<div style="color: #dc3545; font-style: italic;">Error loading tickets: ${error.message}</div>`;
        }
    }

    displayTickets(tickets) {
        const ticketsList = document.getElementById('tickets-list');
        if (!ticketsList || tickets.length === 0) {
            ticketsList.innerHTML = '';
            return;
        }

        ticketsList.innerHTML = tickets.map(ticket => {
            const ticketNumber = JiraUtils.extractTicketNumber(ticket.ticket_id);
            const jiraUrl = `https://hp-jira.external.hp.com/browse/${ticketNumber}`;
            
            return `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; margin-bottom: 8px; 
                            background: #fff; border: 1px solid #e1e5e9; border-radius: 6px; transition: all 0.15s ease;"
                     onmouseover="this.style.backgroundColor='#f8f9fa'; this.style.borderColor='#d0d7de';"
                     onmouseout="this.style.backgroundColor='#fff'; this.style.borderColor='#e1e5e9';">
                    <div style="flex: 1; padding-right: 16px; word-wrap: break-word;">
                        <a href="${jiraUrl}" target="_blank" style="color: #007bff; text-decoration: none;" title="${jiraUrl}">
                            ${ticketNumber}
                        </a>
                    </div>
                    <button onclick="jiraWidget.deleteTicket('${ticket.index}')"
                            style="background: none; border: none; cursor: pointer; padding: 6px; color: #656d76; font-size: 14px; 
                                   border-radius: 4px; opacity: 0.7;"
                            onmouseover="this.style.backgroundColor='#f3f4f6'; this.style.color='#dc2626'; this.style.opacity='1';"
                            onmouseout="this.style.backgroundColor='transparent'; this.style.color='#656d76'; this.style.opacity='0.7';"
                            title="Delete ticket">✕</button>
                </div>
            `;
        }).join('');
    }

    async deleteTicket(index) {
        if (!confirm('Delete ticket?') || !this.projectId || !this.buildId) return;

        try {
            const url = JiraUtils.buildApiUrl(this.projectId, this.buildId, 'jira', index);
            const response = await JiraUtils.apiCall(url, { method: 'DELETE' });
            const data = await response.json();
            
            if (data.message) {
                this.loadTickets();
            } else {
                alert('Error deleting ticket');
            }
        } catch (error) {
            alert('Error deleting ticket');
        }
    }

    render() {
        const container = document.querySelector("[data-id='jira-tickets-widget']");
        if (container?.children[1]) {
            container.children[1].innerHTML = this.createTemplate();
            setTimeout(() => {
                this.setupEventHandlers();
                this.loadTickets();
            }, 100);
        }
        return "";
    }
}

let jiraWidget;

const JiraTicketsWidgetView = Backbone.Marionette.View.extend({
    template: () => "",
    initialize() {
        jiraWidget = new JiraTicketsWidget();
    },
    render() {
        return jiraWidget.render();
    }
});

allure.api.addWidget('widgets', 'jira-tickets-widget', JiraTicketsWidgetView);
