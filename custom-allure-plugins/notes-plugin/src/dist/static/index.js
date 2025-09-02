const NotesUtils = {
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
    
    buildApiUrl: (projectId, buildId, endpoint = 'notes', index = '') => 
        `http://10.223.20.65:5050/allure-docker-service/api/${endpoint}/${projectId}/${buildId}${index ? '/' + index : ''}`,
    
    addLensVersion: (url) => {
        const version = NotesUtils.getLensDesktopVersion();
        return version ? `${url}?lensDesktopVersion=${encodeURIComponent(version)}` : url;
    },
    
    apiCall: async (url, options = {}) => {
        url = NotesUtils.addLensVersion(url);
        return fetch(url, options);
    }
};

class NotesWidget {
    constructor() {
        this.projectId = null;
        this.buildId = null;
        this.init();
    }

    init() {
        const ids = NotesUtils.parseUrl();
        this.projectId = ids.projectId;
        this.buildId = ids.buildId;
        
        if (this.buildId === 'latest' && this.projectId) {
            this.getActualReportId();
        }
    }

    async getActualReportId() {
        try {
            const response = await fetch(`http://10.223.20.65:5050/projects/${this.projectId}`);
            const data = await response.json();
            if (data.data?.project?.reports_id?.length > 1) {
                this.buildId = data.data.project.reports_id[1];
            }
        } catch (error) {
            console.error('[NOTES] Error fetching project data:', error);
        }
    }

    createTemplate() {
        return `
            <div>
                <h2 style="margin-top: 0; font-weight: normal;">NOTES</h2>
                <div class="data-section">
                    <div style="display: flex; gap: 10px; margin-bottom: 20px;">
                        <textarea id="note-input" placeholder="Add a new note..." 
                               style="flex: 1; padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; outline: none; resize: none; font-family: inherit; height: 36px; min-height: 36px; max-height: 200px; overflow-y: hidden;"></textarea>
                        <button id="save-note-btn" 
                                style="padding: 8px 16px; background-color: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; align-self: flex-start;">
                            Add
                        </button>
                    </div>
                    <div id="notes-list" style="min-height: 0; margin-bottom: 20px;"></div>
                </div>
            </div>
        `;
    }

    setupEventHandlers() {
        const saveBtn = document.getElementById('save-note-btn');
        const noteInput = document.getElementById('note-input');
        
        if (!saveBtn || !noteInput) return;

        noteInput.addEventListener('input', function() {
            this.style.height = this.value.trim() === '' ? '36px' : 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
        });

        saveBtn.onclick = () => this.saveNote(noteInput.value.trim());
    }

    async saveNote(noteText) {
        if (!noteText) return alert('Please enter a note');
        if (!this.projectId || !this.buildId) return alert('Unable to determine project/build from URL');

        try {
            const url = NotesUtils.buildApiUrl(this.projectId, this.buildId);
            const response = await NotesUtils.apiCall(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ note: noteText })
            });
            
            const data = await response.json();
            if (data.message) {
                alert('Note saved!');
                document.getElementById('note-input').value = '';
                document.getElementById('note-input').style.height = '36px';
                this.loadNotes();
            } else {
                alert('Error: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            alert('Error: ' + error.message);
        }
    }

    async loadNotes() {
        const notesList = document.getElementById('notes-list');
        if (!notesList || !this.projectId || !this.buildId) return;

        try {
            const url = NotesUtils.buildApiUrl(this.projectId, this.buildId);
            const response = await NotesUtils.apiCall(url);
            
            if (response.status === 404) {
                notesList.innerHTML = '';
                return;
            }

            const data = await response.json();
            if (!data || Object.keys(data).length === 0) {
                notesList.innerHTML = '';
                return;
            }

            const notes = Object.keys(data).map(key => ({
                content: data[key].content || data[key],
                index: key
            })).sort((a, b) => parseInt(b.index) - parseInt(a.index));

            this.displayNotes(notes);
        } catch (error) {
            notesList.innerHTML = `<div style="color: #dc3545; font-style: italic;">Error loading notes: ${error.message}</div>`;
        }
    }

    displayNotes(notes) {
        const notesList = document.getElementById('notes-list');
        if (!notesList || notes.length === 0) {
            notesList.innerHTML = '';
            return;
        }

        notesList.innerHTML = notes.map(note => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; margin-bottom: 8px; 
                        background: #fff; border: 1px solid #e1e5e9; border-radius: 6px; transition: all 0.15s ease;"
                 onmouseover="this.style.backgroundColor='#f8f9fa'; this.style.borderColor='#d0d7de';"
                 onmouseout="this.style.backgroundColor='#fff'; this.style.borderColor='#e1e5e9';">
                <div style="flex: 1; padding-right: 16px; word-wrap: break-word;">
                    ${note.content.replace(/(https?:\/\/[^\s]+)/g, '<a href="$1" target="_blank">$1</a>')}
                </div>
                <button onclick="notesWidget.deleteNote('${note.index}')"
                        style="background: none; border: none; cursor: pointer; padding: 6px; color: #656d76; font-size: 14px; 
                               border-radius: 4px; opacity: 0.7;"
                        onmouseover="this.style.backgroundColor='#f3f4f6'; this.style.color='#dc2626'; this.style.opacity='1';"
                        onmouseout="this.style.backgroundColor='transparent'; this.style.color='#656d76'; this.style.opacity='0.7';"
                        title="Delete note">✕</button>
            </div>
        `).join('');
    }

    async deleteNote(index) {
        if (!confirm('Delete note?') || !this.projectId || !this.buildId) return;

        try {
            const url = NotesUtils.buildApiUrl(this.projectId, this.buildId, 'notes', index);
            const response = await NotesUtils.apiCall(url, { method: 'DELETE' });
            const data = await response.json();
            
            if (data.message) {
                this.loadNotes();
            } else {
                alert('Error deleting note');
            }
        } catch (error) {
            alert('Error deleting note');
        }
    }

    render() {
        const container = document.querySelector("[data-id='notes-widget']");
        if (container?.children[1]) {
            container.children[1].innerHTML = this.createTemplate();
            setTimeout(() => {
                this.setupEventHandlers();
                this.loadNotes();
            }, 100);
        }
        return "";
    }
}

let notesWidget;

const NotesWidgetView = Backbone.Marionette.View.extend({
    template: () => "",
    initialize() {
        notesWidget = new NotesWidget();
    },
    render() {
        return notesWidget.render();
    }
});

allure.api.addWidget('widgets', 'notes-widget', NotesWidgetView);
