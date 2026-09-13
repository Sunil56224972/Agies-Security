const { execFileSync } = require('child_process');
const ffmpegPath = require('ffmpeg-static');
const path = require('path');

const inputFile = path.join(__dirname, 'aegis_official_workflow_4min.webp');
const outputFile = path.join(__dirname, 'aegis_demo_4min.mp4');

console.log('Starting conversion...');
console.log('Input :', inputFile);
console.log('Output:', outputFile);
console.log('FFmpeg:', ffmpegPath);

try {
  execFileSync(ffmpegPath, [
    '-y',
    '-i', inputFile,
    '-c:v', 'libx264',
    '-pix_fmt', 'yuv420p',
    '-vf', 'scale=trunc(iw/2)*2:trunc(ih/2)*2',
    '-preset', 'fast',
    '-crf', '20',
    outputFile
  ], { stdio: 'inherit' });
  console.log('\nConversion complete! Output:', outputFile);
} catch (err) {
  console.error('Conversion failed:', err.message);
  process.exit(1);
}
