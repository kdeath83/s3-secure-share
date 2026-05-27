from mangum import Mangum
from app import app

# AWS Lambda entry point
handler = Mangum(app, lifespan="off")