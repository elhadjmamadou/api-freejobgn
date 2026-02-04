"""
Tests pour les endpoints de documents freelance:
- GET /api/auth/freelance/documents/
- POST /api/auth/freelance/documents/
- GET /api/auth/freelance/documents/<pk>/
- PATCH /api/auth/freelance/documents/<pk>/
- DELETE /api/auth/freelance/documents/<pk>/
"""

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework import status

from users.models import FreelanceDocument, FreelanceDocumentType


# ============================================================
# URLs
# ============================================================

DOCUMENTS_URL = "/api/auth/freelance/documents/"


def document_detail_url(pk):
    """Retourne l'URL de détail d'un document."""
    return f"{DOCUMENTS_URL}{pk}/"


# ============================================================
# Tests: GET /api/auth/freelance/documents/
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentList:
    """Tests pour l'endpoint GET /api/auth/freelance/documents/"""

    def test_list_documents_success(self, auth_client, freelance_document):
        """
        200: Liste des documents du freelance connecté.
        """
        response = auth_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        # Peut être paginé ou non
        results = data.get("results", data)
        assert len(results) >= 1
        assert any(doc["id"] == freelance_document.id for doc in results)

    def test_list_documents_empty(self, auth_client, provider_profile):
        """
        200: Liste vide si aucun document.
        """
        response = auth_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        results = data.get("results", data)
        assert len(results) == 0

    def test_list_documents_filter_by_doc_type(self, auth_client, provider_profile):
        """
        200: Filtre ?doc_type=CV retourne uniquement les CV.
        """
        # Créer plusieurs documents de types différents
        cv_file = SimpleUploadedFile("cv.pdf", b"cv content", content_type="application/pdf")
        cert_file = SimpleUploadedFile("cert.pdf", b"cert content", content_type="application/pdf")

        FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.CV,
            file=cv_file,
            title="Mon CV",
        )
        FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.CERTIFICATION,
            file=cert_file,
            title="Ma certification",
        )

        response = auth_client.get(DOCUMENTS_URL, {"doc_type": "CV"})

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        results = data.get("results", data)
        assert len(results) == 1
        assert results[0]["doc_type"] == "CV"

    def test_list_documents_ordered_by_created_at_desc(self, auth_client, provider_profile):
        """
        200: Documents ordonnés par -created_at (plus récent en premier).
        """
        file1 = SimpleUploadedFile("doc1.pdf", b"content1", content_type="application/pdf")
        file2 = SimpleUploadedFile("doc2.pdf", b"content2", content_type="application/pdf")

        doc1 = FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.CV,
            file=file1,
            title="Premier doc",
        )
        doc2 = FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.PORTFOLIO,
            file=file2,
            title="Second doc",
        )

        response = auth_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        results = data.get("results", data)
        assert len(results) >= 2
        # Le second document (créé après) doit être en premier
        assert results[0]["id"] == doc2.id
        assert results[1]["id"] == doc1.id

    def test_list_documents_isolation_cannot_see_others(
        self, auth_client, freelance_document, other_freelance_document
    ):
        """
        200: Un freelance ne voit que ses propres documents.
        """
        response = auth_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        results = data.get("results", data)

        # Vérifie qu'on ne voit que les documents du freelance connecté
        doc_ids = [doc["id"] for doc in results]
        assert freelance_document.id in doc_ids
        assert other_freelance_document.id not in doc_ids

    def test_list_documents_unauthenticated(self, api_client):
        """
        401: Utilisateur non authentifié.
        """
        response = api_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_list_documents_forbidden_client(self, api_client, client_user):
        """
        403: Un client ne peut pas accéder aux documents freelance.
        """
        api_client.force_authenticate(user=client_user)
        response = api_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests: POST /api/auth/freelance/documents/
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentCreate:
    """Tests pour l'endpoint POST /api/auth/freelance/documents/"""

    def test_create_document_success_minimal(self, auth_client, provider_profile, sample_pdf_file):
        """
        201: Upload réussi avec champs requis (doc_type, file).
        """
        payload = {
            "doc_type": "CV",
            "file": sample_pdf_file,
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_201_CREATED

        data = response.json()
        assert data["doc_type"] == "CV"
        assert "file" in data
        assert FreelanceDocument.objects.filter(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.CV,
        ).exists()

    def test_create_document_success_with_optional_fields(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        201: Upload réussi avec tous les champs optionnels.
        """
        payload = {
            "doc_type": "CERTIFICATION",
            "file": sample_pdf_file,
            "title": "AWS Certification",
            "reference_number": "CERT-2024-001",
            "issued_at": "2024-01-15",
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_201_CREATED

        data = response.json()
        assert data["doc_type"] == "CERTIFICATION"
        assert data["title"] == "AWS Certification"
        assert data["reference_number"] == "CERT-2024-001"
        assert data["issued_at"] == "2024-01-15"

    def test_create_document_validation_doc_type_required(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        400: doc_type est requis.
        """
        payload = {
            "file": sample_pdf_file,
            # doc_type manquant
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "doc_type" in response.json()

    def test_create_document_validation_file_required(self, auth_client, provider_profile):
        """
        400: file est requis.
        """
        payload = {
            "doc_type": "CV",
            # file manquant
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "file" in response.json()

    def test_create_document_validation_rccm_forbidden_for_freelance(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        400: doc_type RCCM interdit pour un freelance (réservé agence).
        """
        payload = {
            "doc_type": "RCCM",
            "file": sample_pdf_file,
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        data = response.json()
        assert "doc_type" in data or "réservé" in str(data).lower() or "agence" in str(data).lower()

    def test_create_document_validation_statutes_forbidden_for_freelance(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        400: doc_type STATUTES interdit pour un freelance (réservé agence).
        """
        payload = {
            "doc_type": "STATUTES",
            "file": sample_pdf_file,
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_document_validation_tax_forbidden_for_freelance(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        400: doc_type TAX interdit pour un freelance (réservé agence).
        """
        payload = {
            "doc_type": "TAX",
            "file": sample_pdf_file,
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_create_document_forces_provider_profile(
        self, auth_client, provider_profile, sample_pdf_file
    ):
        """
        201: Le provider_profile est forcé à celui de l'utilisateur connecté.
        """
        payload = {
            "doc_type": "CV",
            "file": sample_pdf_file,
        }

        response = auth_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_201_CREATED

        doc = FreelanceDocument.objects.latest("created_at")
        assert doc.provider_profile == provider_profile

    def test_create_document_unauthenticated(self, api_client, sample_pdf_file):
        """
        401: Utilisateur non authentifié.
        """
        payload = {
            "doc_type": "CV",
            "file": sample_pdf_file,
        }

        response = api_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_create_document_forbidden_client(self, api_client, client_user, sample_pdf_file):
        """
        403: Un client ne peut pas uploader de documents freelance.
        """
        api_client.force_authenticate(user=client_user)
        payload = {
            "doc_type": "CV",
            "file": sample_pdf_file,
        }

        response = api_client.post(DOCUMENTS_URL, payload, format="multipart")

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests: GET /api/auth/freelance/documents/<pk>/
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentDetail:
    """Tests pour l'endpoint GET /api/auth/freelance/documents/<pk>/"""

    def test_get_document_success(self, auth_client, freelance_document):
        """
        200: Récupération d'un document appartenant au freelance.
        """
        url = document_detail_url(freelance_document.id)
        response = auth_client.get(url)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        assert data["id"] == freelance_document.id
        assert data["doc_type"] == freelance_document.doc_type
        assert data["title"] == freelance_document.title

    def test_get_document_not_found_other_user(
        self, auth_client, other_freelance_document
    ):
        """
        404: Document appartenant à un autre freelance.
        """
        url = document_detail_url(other_freelance_document.id)
        response = auth_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_document_not_found_invalid_id(self, auth_client, provider_profile):
        """
        404: Document avec ID inexistant.
        """
        url = document_detail_url(99999)
        response = auth_client.get(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_document_unauthenticated(self, api_client, freelance_document):
        """
        401: Utilisateur non authentifié.
        """
        url = document_detail_url(freelance_document.id)
        response = api_client.get(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================
# Tests: PATCH /api/auth/freelance/documents/<pk>/
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentUpdate:
    """Tests pour l'endpoint PATCH /api/auth/freelance/documents/<pk>/"""

    def test_patch_document_success_title(self, auth_client, freelance_document):
        """
        200: Mise à jour du title.
        """
        url = document_detail_url(freelance_document.id)
        payload = {"title": "CV mis à jour"}

        response = auth_client.patch(url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        freelance_document.refresh_from_db()
        assert freelance_document.title == "CV mis à jour"

    def test_patch_document_success_replace_file(
        self, auth_client, freelance_document, sample_txt_file
    ):
        """
        200: Remplacement du fichier.
        """
        url = document_detail_url(freelance_document.id)
        payload = {"file": sample_txt_file}

        response = auth_client.patch(url, payload, format="multipart")

        assert response.status_code == status.HTTP_200_OK

        freelance_document.refresh_from_db()
        # Vérifie que le fichier a été mis à jour (nom différent)
        assert "test_document" in freelance_document.file.name

    def test_patch_document_success_reference_number(self, auth_client, freelance_document):
        """
        200: Mise à jour du reference_number.
        """
        url = document_detail_url(freelance_document.id)
        payload = {"reference_number": "REF-2024-UPDATE"}

        response = auth_client.patch(url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        freelance_document.refresh_from_db()
        assert freelance_document.reference_number == "REF-2024-UPDATE"

    def test_patch_document_success_issued_at(self, auth_client, freelance_document):
        """
        200: Mise à jour de issued_at.
        """
        url = document_detail_url(freelance_document.id)
        payload = {"issued_at": "2025-06-01"}

        response = auth_client.patch(url, payload, format="json")

        assert response.status_code == status.HTTP_200_OK

        freelance_document.refresh_from_db()
        assert str(freelance_document.issued_at) == "2025-06-01"

    def test_patch_document_cannot_change_provider_profile(
        self, auth_client, freelance_document, other_provider_profile
    ):
        """
        200/ignored: Tenter de changer provider_profile ne doit pas fonctionner.
        Le champ provider_profile doit être ignoré ou rejeté.
        """
        url = document_detail_url(freelance_document.id)
        original_profile_id = freelance_document.provider_profile_id

        payload = {
            "title": "Test",
            # Tentative de changement de provider_profile (doit être ignoré)
            "provider_profile": other_provider_profile.id,
        }

        response = auth_client.patch(url, payload, format="json")

        # La requête peut réussir mais provider_profile ne doit pas changer
        freelance_document.refresh_from_db()
        assert freelance_document.provider_profile_id == original_profile_id

    def test_patch_document_not_found_other_user(
        self, auth_client, other_freelance_document
    ):
        """
        404: Tentative de modifier un document d'un autre freelance.
        """
        url = document_detail_url(other_freelance_document.id)
        payload = {"title": "Hacked title"}

        response = auth_client.patch(url, payload, format="json")

        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Vérifie que le document n'a pas été modifié
        other_freelance_document.refresh_from_db()
        assert other_freelance_document.title != "Hacked title"

    def test_patch_document_unauthenticated(self, api_client, freelance_document):
        """
        401: Utilisateur non authentifié.
        """
        url = document_detail_url(freelance_document.id)
        payload = {"title": "Test"}

        response = api_client.patch(url, payload, format="json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


# ============================================================
# Tests: DELETE /api/auth/freelance/documents/<pk>/
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentDelete:
    """Tests pour l'endpoint DELETE /api/auth/freelance/documents/<pk>/"""

    def test_delete_document_success(self, auth_client, freelance_document):
        """
        204: Suppression réussie de son propre document.
        """
        doc_id = freelance_document.id
        url = document_detail_url(doc_id)

        response = auth_client.delete(url)

        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not FreelanceDocument.objects.filter(id=doc_id).exists()

    def test_delete_document_not_found_other_user(
        self, auth_client, other_freelance_document
    ):
        """
        404: Tentative de supprimer un document d'un autre freelance.
        """
        url = document_detail_url(other_freelance_document.id)

        response = auth_client.delete(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Vérifie que le document existe toujours
        assert FreelanceDocument.objects.filter(id=other_freelance_document.id).exists()

    def test_delete_document_not_found_invalid_id(self, auth_client, provider_profile):
        """
        404: Document avec ID inexistant.
        """
        url = document_detail_url(99999)

        response = auth_client.delete(url)

        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_document_unauthenticated(self, api_client, freelance_document):
        """
        401: Utilisateur non authentifié.
        """
        url = document_detail_url(freelance_document.id)

        response = api_client.delete(url)

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_delete_document_forbidden_client(
        self, api_client, client_user, freelance_document
    ):
        """
        403: Un client ne peut pas supprimer de documents freelance.
        """
        api_client.force_authenticate(user=client_user)
        url = document_detail_url(freelance_document.id)

        response = api_client.delete(url)

        assert response.status_code == status.HTTP_403_FORBIDDEN


# ============================================================
# Tests d'isolation
# ============================================================


@pytest.mark.django_db
class TestFreelanceDocumentIsolation:
    """Tests d'isolation: un freelance ne peut accéder qu'à ses propres documents."""

    def test_list_only_own_documents(
        self, auth_client, provider_profile, other_provider_profile
    ):
        """
        Un freelance ne voit que ses propres documents dans la liste.
        """
        # Documents du freelance connecté
        file1 = SimpleUploadedFile("my_cv.pdf", b"my cv", content_type="application/pdf")
        my_doc = FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.CV,
            file=file1,
            title="Mon CV",
        )

        # Documents de l'autre freelance
        file2 = SimpleUploadedFile("other_cv.pdf", b"other cv", content_type="application/pdf")
        other_doc = FreelanceDocument.objects.create(
            provider_profile=other_provider_profile,
            doc_type=FreelanceDocumentType.CV,
            file=file2,
            title="CV de l'autre",
        )

        response = auth_client.get(DOCUMENTS_URL)

        assert response.status_code == status.HTTP_200_OK

        data = response.json()
        results = data.get("results", data)
        doc_ids = [doc["id"] for doc in results]

        assert my_doc.id in doc_ids
        assert other_doc.id not in doc_ids

    def test_detail_only_own_documents(
        self, auth_client, freelance_document, other_freelance_document
    ):
        """
        Un freelance peut voir le détail de ses documents mais pas ceux des autres.
        """
        # Peut voir son propre document
        response = auth_client.get(document_detail_url(freelance_document.id))
        assert response.status_code == status.HTTP_200_OK

        # Ne peut pas voir le document de l'autre
        response = auth_client.get(document_detail_url(other_freelance_document.id))
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_update_only_own_documents(
        self, auth_client, freelance_document, other_freelance_document
    ):
        """
        Un freelance peut modifier ses documents mais pas ceux des autres.
        """
        # Peut modifier son propre document
        response = auth_client.patch(
            document_detail_url(freelance_document.id),
            {"title": "Nouveau titre"},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK

        # Ne peut pas modifier le document de l'autre
        response = auth_client.patch(
            document_detail_url(other_freelance_document.id),
            {"title": "Titre hacké"},
            format="json",
        )
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_only_own_documents(
        self, auth_client, provider_profile, other_provider_profile
    ):
        """
        Un freelance peut supprimer ses documents mais pas ceux des autres.
        """
        # Documents du freelance connecté
        file1 = SimpleUploadedFile("to_delete.pdf", b"delete me", content_type="application/pdf")
        my_doc = FreelanceDocument.objects.create(
            provider_profile=provider_profile,
            doc_type=FreelanceDocumentType.OTHER,
            file=file1,
        )

        # Documents de l'autre freelance
        file2 = SimpleUploadedFile("protected.pdf", b"protected", content_type="application/pdf")
        other_doc = FreelanceDocument.objects.create(
            provider_profile=other_provider_profile,
            doc_type=FreelanceDocumentType.OTHER,
            file=file2,
        )

        # Peut supprimer son propre document
        response = auth_client.delete(document_detail_url(my_doc.id))
        assert response.status_code == status.HTTP_204_NO_CONTENT

        # Ne peut pas supprimer le document de l'autre
        response = auth_client.delete(document_detail_url(other_doc.id))
        assert response.status_code == status.HTTP_404_NOT_FOUND

        # Vérifie que le document de l'autre existe toujours
        assert FreelanceDocument.objects.filter(id=other_doc.id).exists()
