-- Azure Container Registry (ACR) and Generic Docker Registry V2 as first-class registry types.
ALTER TYPE registry_type ADD VALUE 'acr';
ALTER TYPE registry_type ADD VALUE 'generic';
