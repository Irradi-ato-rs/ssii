// src/pages/api/v1/compute.ts

// ... inside loop over rows (i) ...
let vi = 1;
const weights = [0.4, 0.3, 0.3]; // E1, E2, E3

for (let j = 0; j < 3; j++) {
  const score = C[i][j] || 0;
  
  // Theorem 1: Zero Property (Risk Switch)
  if (score === 0) { 
    vi = 0; 
    break; 
  }
  
  // Geometric Aggregation (Theorem 2)
  vi *= Math.pow(score, weights[j]);
}

// Store vi in rowValidations array...   