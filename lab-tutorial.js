// Check for lab ID in URL
const urlParams = new URLSearchParams(window.location.search);
const labId = urlParams.get('lab');

if (labId) {
  // Fetch lab data from lab-data.js (assuming it's loaded globally or we fetch it)
  // For now, we'll assume labData is available globally from lab-data.js
  // If labData is not defined, we'll use a fallback or error out.
  
  // This is a placeholder for dynamic content loading
  // In a real app, this would load the specific lab content based on labId
  // For this static version, we'll proceed with the existing content
  
  // Checkbox persistence logic
  const completionKey = `lab-complete-${labId}`;
  const checkboxes = document.querySelectorAll('.step-checkbox');

  // Load state
  checkboxes.forEach(cb => {
    const state = localStorage.getItem(cb.id);
    if (state === 'checked') {
      cb.checked = true;
    }
  });

  // Save state on change
  checkboxes.forEach(cb => {
    cb.addEventListener('change', function() {
      if (this.checked) {
        localStorage.setItem(this.id, 'checked');
      } else {
        localStorage.removeItem(this.id);
      }
    });
  });

  // Step toggle functionality (Final, robust fix)
  // Attach listener to the parent container and use event delegation
  document.querySelector('.tutorial-steps').addEventListener('click', function(event) {
    const btn = event.target.closest('.step-toggle');
    if (!btn) return; // Not a toggle button
    
    const step = btn.closest('.tutorial-step');
    // Toggle the 'expanded' class on the parent element
    const isExpanded = step.classList.toggle('expanded');
    
    // Update the button text
    btn.textContent = isExpanded ? 'Collapse' : 'Expand';
  });

  // Knowledge check (Keep existing)
  window.checkKnowledge = function() {
    const questions = document.querySelectorAll('.kq-item');
    let correct = 0;
    let total = questions.length;
    
    questions.forEach(q => {
      q.classList.remove('correct', 'incorrect'); // Clear previous feedback
      const correctAnswer = q.querySelector('input[data-correct]');
      const selected = q.querySelector('input:checked');
      
      // Find the label corresponding to the correct answer input
      const correctLabel = correctAnswer.closest('label');
      
      if (selected) {
        if (selected === correctAnswer) {
          correct++;
          q.classList.add('correct');
          selected.closest('label').classList.add('correct-answer');
        } else {
          q.classList.add('incorrect');
          selected.closest('label').classList.add('incorrect-answer');
          correctLabel.classList.add('correct-answer'); // Highlight the correct answer
        }
      } else {
        // If no answer is selected, just highlight the correct one
        correctLabel.classList.add('correct-answer');
      }
    });
    
    // Add a result message element for better feedback than an alert
    let resultMessage = document.getElementById('quiz-result-message');
    if (!resultMessage) {
      resultMessage = document.createElement('p');
      resultMessage.id = 'quiz-result-message';
      resultMessage.style.marginTop = '15px';
      resultMessage.style.padding = '10px';
      resultMessage.style.borderRadius = '5px';
      resultMessage.style.fontWeight = 'bold';
      document.querySelector('.knowledge-check-section').appendChild(resultMessage);
    }
    
    if (correct === total) {
      resultMessage.textContent = `✅ Excellent work! You got all ${total} questions correct!`;
      resultMessage.style.backgroundColor = 'var(--color-success-bg)';
      resultMessage.style.color = 'var(--color-success-text)';
    } else {
      resultMessage.textContent = `❌ You got ${correct} out of ${total} correct. Review the highlighted correct answers and try again.`;
      resultMessage.style.backgroundColor = 'var(--color-error-bg)';
      resultMessage.style.color = 'var(--color-error-text)';
    }
  }

  // Mark Complete function (Update key)
  window.markComplete = function() {
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    if (allChecked) {
      localStorage.setItem(completionKey, 'true');
      alert(`🎉 Congratulations! Lab ${labId} marked as complete!`);
      window.location.href = 'lab.html';
    } else {
      alert('Please complete all checklist items before marking as complete.');
    }
  }

  

  // Initialize - expand first step
  document.querySelector('.tutorial-step').classList.add('expanded');
  document.querySelector('.tutorial-step').querySelector('.step-toggle').textContent = 'Collapse';

} else {
  // Fallback for invalid lab ID
  window.location.href = 'lab-tutorial.html?lab=1.1';
}
