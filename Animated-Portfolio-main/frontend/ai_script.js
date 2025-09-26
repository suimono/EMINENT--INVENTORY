document.addEventListener("DOMContentLoaded", () => {
    // Elemen-elemen dari Jendela Chat AI
    const aiFab = document.getElementById('aiAssistantFab');
    const aiChatWindow = document.getElementById('aiChatWindow');
    const closeAiChatBtn = document.getElementById('closeAiChatBtn');
    const aiChatMessages = document.getElementById('aiChatMessages');
    const aiChatMessageInput = document.getElementById('aiChatMessageInput');
    const sendAiChatMessageBtn = document.getElementById('sendAiChatMessageBtn');
    const quickActionsContainer = document.getElementById('aiQuickActions'); // Menggunakan container

    // Riwayat percakapan untuk dikirim ke AI
    let aiChatHistory = [];

    // URL Backend Anda
    const backendApiUrl = 'http://localhost:3000/api/ai/chat';

    // Fungsi untuk menampilkan/menyembunyikan jendela chat
    function toggleAiChatWindow() {
        if (!aiChatWindow) return;

        const isActive = aiChatWindow.classList.contains('active');
        aiChatWindow.classList.toggle('active', !isActive);
        aiChatWindow.classList.toggle('inactive', isActive);
        aiChatWindow.classList.remove('hidden');

        if (!isActive) {
            // Tampilkan jendela
            if (aiChatMessages.childElementCount === 0) {
                addMessageToChat("Halo! Saya Asisten AI Eminent. Ada yang bisa saya bantu?", 'ai');
            }
            aiChatMessageInput.focus();
        } else {
            // Sembunyikan jendela setelah animasi selesai
            setTimeout(() => {
                if (!aiChatWindow.classList.contains('active')) {
                    aiChatWindow.classList.add('hidden');
                }
            }, 250);
        }
    }

    // Fungsi untuk menambahkan pesan ke tampilan chat
    function addMessageToChat(text, sender, isLoading = false) {
        if (!aiChatMessages) return null;
        
        // Hapus indikator "mengetik" jika ada, sebelum menambahkan pesan baru
        const existingTypingIndicator = aiChatMessages.querySelector('.typing');
        if (existingTypingIndicator) {
            existingTypingIndicator.remove();
        }

        const messageDiv = document.createElement('div');
        messageDiv.className = `animate-fade-in-up ${sender === 'user' ? 'user-message' : 'ai-message'}`;

        if (isLoading) {
            messageDiv.classList.add('typing');
            messageDiv.innerHTML = '<span></span><span></span><span></span>';
        } else {
            messageDiv.textContent = text;
        }

        aiChatMessages.appendChild(messageDiv);
        aiChatMessages.scrollTop = aiChatMessages.scrollHeight;
        return messageDiv;
    }

    // Fungsi untuk mengirim pesan ke backend
    async function sendAiQuery(promptText) {
        if (!promptText.trim()) return;

        addMessageToChat(promptText, 'user');
        aiChatHistory.push({ role: "user", parts: [{ text: promptText }] });

        sendAiChatMessageBtn.disabled = true;
        quickActionsContainer.querySelectorAll('button').forEach(btn => btn.disabled = true);
        
        addMessageToChat('', 'ai', true); // Tampilkan indikator mengetik

        try {
            const response = await fetch(backendApiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ prompt: promptText, history: aiChatHistory })
            });

            const result = await response.json();

            if (!response.ok) {
                // Gunakan pesan error dari backend jika ada, jika tidak, buat pesan default
                throw new Error(result.message || `Server merespons dengan error ${response.status}`);
            }

            if (result.success && result.response) {
                addMessageToChat(result.response, 'ai');
                aiChatHistory.push({ role: "model", parts: [{ text: result.response }] });
            } else {
                throw new Error(result.message || "Respons dari AI tidak valid.");
            }

        } catch (error) {
            console.error('[FRONTEND AI] Fetch Error:', error);
            let errorMessage = "Maaf, terjadi kesalahan koneksi atau server AI tidak dapat dijangkau.";
            if (error.message.includes('fetch')) {
                 errorMessage = "Tidak dapat terhubung ke server AI. Pastikan backend berjalan.";
            } else {
                errorMessage = error.message;
            }
            addMessageToChat(errorMessage, 'ai');
        } finally {
            sendAiChatMessageBtn.disabled = false;
            quickActionsContainer.querySelectorAll('button').forEach(btn => btn.disabled = false);
            aiChatMessageInput.focus();
        }
    }

    // --- EVENT LISTENERS ---
    if (aiFab) aiFab.addEventListener('click', toggleAiChatWindow);
    if (closeAiChatBtn) closeAiChatBtn.addEventListener('click', toggleAiChatWindow);

    if (sendAiChatMessageBtn) {
        sendAiChatMessageBtn.addEventListener('click', () => {
            const text = aiChatMessageInput.value;
            sendAiQuery(text);
            aiChatMessageInput.value = '';
        });
    }

    if (aiChatMessageInput) {
        aiChatMessageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !sendAiChatMessageBtn.disabled) {
                const text = aiChatMessageInput.value;
                sendAiQuery(text);
                aiChatMessageInput.value = '';
            }
        });
    }

    if (quickActionsContainer) {
        quickActionsContainer.addEventListener('click', (e) => {
            const button = e.target.closest('.ai-quick-action-btn');
            if (button) {
                const prompt = button.querySelector('span').textContent.trim();
                sendAiQuery(prompt);
            }
        });
    }
});
